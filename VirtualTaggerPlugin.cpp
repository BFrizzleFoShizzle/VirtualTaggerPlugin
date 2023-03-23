#include "VirtualTaggerPlugin.h"

#include <MainWindow.h>

#include <qapplication.h>
#include <qclipboard.h>
#include <qelapsedtimer.h>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
// I couldn't find working plugin config/setting APIs in Cutter, so use Qt's
#include <QSettings>

#include <fstream>

#include <thread>
#include <mutex>

// Adapted from "SamplePlugin" examples from the Cutter repo (GPLv3)

void VirtualTaggerPlugin::setupPlugin() {}

static std::mutex mutex;

static const char* GENERATE_X_REFS_SETTING = "GenrateXRefs";
static const char* CLEAR_STRINGS_SETTING = "ClearStrings";
static const char* SET_DATA_SETTING = "SetData";
static const char* TAG_PURE_VIRTUALS_SETTING = "TagPureVirtuals";
static const char* ADD_NAME_COMMENT = "AddNameComment";
static const char* GENERATE_FUNCTION_ENTRIES = "GenerateFunctionEntries";
static const char* ANALYSE_ADDED_FUNCTIONS = "AnalyseAddedFunctions";
static const char* RECURSIVE_ANALYSIS = "RecursiveAnalysis";
static const char* PROPAGATE_NORETURN = "PropagateNoreturn";
static const char* USE_ANALYSIS_FUNCTION_ADD = "UseAnalysisFunctionAdd";

// rz_core_analysis_function_add replacement
static bool RzAnalysisFunctionAddNoUpdate(RzCore* core, const char* name, size_t addr, bool propagateNoreturn, bool recursive)
{
    int depth = rz_config_get_i(core->config, "analysis.depth");
    RzAnalysisFunction* fcn = NULL;

    // fast
    rz_core_analysis_fcn(core, addr, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, depth);
    // fast
    fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
    if (fcn) {
        /* ensure we use a proper name */
        // fast
        rz_core_analysis_function_rename(core, addr, fcn->name);
        if (core->analysis->opt.vars) {
            // fast
            rz_core_recover_vars(core, fcn, true);
        }
        // fast
        rz_analysis_fcn_vars_add_types(core->analysis, fcn);
    }
    else {
        RZ_LOG_DEBUG("Unable to analyze function at 0x%08" PFMT64x "\n", addr);
    }
    if (recursive) {
        fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0); /// XXX wrong in case of nopskip
        if (fcn) {
            RzAnalysisXRef* xref;
            RzListIter* iter;
            RzList* xrefs = rz_analysis_function_get_xrefs_from(fcn);
            CutterRzListForeach(xrefs, iter, RzAnalysisXRef, xref) {
                if (xref->to == UT64_MAX) {
                    // RZ_LOG_WARN("core: ignore 0x%08"PFMT64x" call 0x%08"PFMT64x"\n", ref->at, ref->addr);
                    continue;
                }
                if (xref->type != RZ_ANALYSIS_XREF_TYPE_CODE && xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
                    /* only follow code/call references */
                    continue;
                }
                if (!rz_io_is_valid_offset(core->io, xref->to, !core->analysis->opt.noncode)) {
                    continue;
                }
                rz_core_analysis_fcn(core, xref->to, fcn->addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
                /* use recursivity here */
                RzAnalysisFunction* f = rz_analysis_get_function_at(core->analysis, xref->to);
                if (f) {
                    RzListIter* iter;
                    RzAnalysisXRef* xref1;
                    RzList* xrefs1 = rz_analysis_function_get_xrefs_from(f);
                    CutterRzListForeach(xrefs1, iter, RzAnalysisXRef, xref1) {
                        if (!rz_io_is_valid_offset(core->io, xref1->to, !core->analysis->opt.noncode)) {
                            continue;
                        }
                        if (xref1->type != RZ_ANALYSIS_XREF_TYPE_CODE && xref1->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
                            continue;
                        }
                        rz_core_analysis_fcn(core, xref1->to, f->addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
                        // recursively follow fcn->refs again and again
                    }
                    rz_list_free(xrefs1);
                }
                else {
                    f = rz_analysis_get_fcn_in(core->analysis, fcn->addr, 0);
                    if (f) {
                        /* cut function */
                        rz_analysis_function_resize(f, addr - fcn->addr);
                        rz_core_analysis_fcn(core, xref->to, fcn->addr,
                            RZ_ANALYSIS_XREF_TYPE_CALL, depth);
                        f = rz_analysis_get_function_at(core->analysis, fcn->addr);
                    }
                    if (!f) {
                        RZ_LOG_ERROR("core: cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
                        rz_list_free(xrefs);
                        return false;
                    }
                }
            }
            rz_list_free(xrefs);
            if (core->analysis->opt.vars) {
                rz_core_recover_vars(core, fcn, true);
            }
        }
    }
    // fast
    if (RZ_STR_ISNOTEMPTY(name) && !rz_core_analysis_function_rename(core, addr, name)) {
        RZ_LOG_ERROR("core: cannot find function at 0x%08" PFMT64x "\n", addr);
        return false;
    }

    // the above is enough to create named function definitions + associate function bodies with the function definition
    
    // slow
    // HACK I think not running this stops the function being put in TODO for rz_core_analysis_flag_every_function
    if(propagateNoreturn)
        rz_core_analysis_propagate_noreturn(core, addr);
    // skip this - we do it after all functions have been processed
    //rz_core_analysis_flag_every_function(core);
    return true;
}

static void runTagger(const SettingsMap &settings)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto core = Core();
    auto rizinCore = core->core();

    core->message("VirtualTaggerPlugin: Running tagger...");

    QElapsedTimer timer;
    timer.start();

    bool generateXRefs = settings.value(GENERATE_X_REFS_SETTING);
    bool clearStrings = settings.value(CLEAR_STRINGS_SETTING);
    bool setToData = settings.value(SET_DATA_SETTING);
    bool tagPureVirtuals = settings.value(TAG_PURE_VIRTUALS_SETTING);
    bool addNameComment = settings.value(ADD_NAME_COMMENT);
    bool generateFunctionEntries = settings.value(GENERATE_FUNCTION_ENTRIES);
    bool analyseAddedFunctions = settings.value(ANALYSE_ADDED_FUNCTIONS);
    bool propagateNoreturn = settings.value(PROPAGATE_NORETURN);
    bool recursiveAnalysis = settings.value(RECURSIVE_ANALYSIS);
    bool useAnalysisFunctionAdd = settings.value(USE_ANALYSIS_FUNCTION_ADD);

    // core->getArchBits() seems to return byte size of pointer? Probably a bug?
    // Rizin gives the correct size, so I'm using that in case Cutter's API changes
    size_t pointerSize = rz_bin_object_get_info(rz_bin_cur_object(rizinCore->bin))->bits / 8;
    //core->message("Bits: " + QString::number(core->getArchBits()) + " bytes: " + QString::number(pointerSize));
    auto classNames = core->getAllAnalysisClasses(false);

    size_t methodDefinitionsCreated = 0;
    size_t stringsRemoved = 0;
    size_t vtableXrefsCreated = 0;

    for (auto className : classNames)
    {
        // update name
        auto methods = core->getAnalysisClassMethods(className);
        auto baseClasses = core->getAnalysisClassBaseClasses(className);
        auto classVTables = core->getAnalysisClassVTables(className);
        if (classVTables.size() > 0)
        {
            if (classVTables[0].addr % pointerSize != 0)
                core->message("VirtualTaggerPlugin: Bad vtable address for " + className);

            // Used to find empty slots without entries
            size_t nextOffset = classVTables[0].addr;

            methodloop:
            for (auto method : methods)
            {
                // pure virtual methods (_purecall) don't have entries, this loop fills
                // in any missing entries + adds the current method
                for (size_t vtableEntryAddr = nextOffset; vtableEntryAddr <= classVTables[0].addr + method.vtableOffset;
                    vtableEntryAddr += pointerSize)
                {
                    // skip straight to method entry if skipping pure functions
                    if (!tagPureVirtuals)
                        vtableEntryAddr = classVTables[0].addr + method.vtableOffset;

                    // Clean up vtable entry
                    // Cutter often misinterprets vtable entries as strings, 
                    // which also messes up Cutter's interpretation after setting to data
                    if (clearStrings)
                    {
                        // TODO we can probably do the whole vtable at once
                        rz_meta_del(rizinCore->analysis, RZ_META_TYPE_STRING, vtableEntryAddr, pointerSize);
                        for (int j = 0; j < pointerSize; ++j)
                        {
                            size_t addr = vtableEntryAddr + j;

                            // early exit
                            if (!rz_flag_exist_at(rizinCore->flags, "str.", 4, addr))
                                continue;

                            // cleanup - clear string flags
                            QStringList flags = core->listFlagsAsStringAt(addr).split(",");;
                            for (auto flag : flags)
                            {
                                if (flag.startsWith("str."))
                                {
                                    // HACK I think the code here clears using the *non-unique* name,
                                    // so this might destroy all definitions of the flag...
                                    // HOWEVER, String defintions in Strings panel still seem to exist.
                                    // Unfortunately, hitting F5 in the strings panel after this freezes 
                                    // Cutter... searches work though?
                                    rz_flag_unset_name(rizinCore->flags, flag.toStdString().c_str());
                                    ++stringsRemoved;
                                }
                            }
                        }
                    }

                    if(setToData)
                        core->setToData(vtableEntryAddr, pointerSize);

                    if (generateXRefs)
                    {
                        // add X-ref to vtable entry
                        rz_analysis_xrefs_set(rizinCore->analysis, vtableEntryAddr, method.addr, RzAnalysisXRefType::RZ_ANALYSIS_XREF_TYPE_DATA);
                        ++vtableXrefsCreated;
                    }

                    // add comment to make reading x-refs easier
                    if (addNameComment)
                    {
                        // Cutter's API is slow, so we set the comment directly via Rizin (sketchy but works since we run early)
                        //core->setComment(vtableEntryAddr, className + "." + method.name);
                        rz_meta_set_string(rizinCore->analysis, RZ_META_TYPE_COMMENT, vtableEntryAddr, (className + "." + method.name).toStdString().c_str());
                    }
                }

                // update for next loop
                nextOffset = classVTables[0].addr + method.vtableOffset + pointerSize;

                // create function definitions
                if (generateFunctionEntries)
                {
                    if (core->functionAt(method.addr) == nullptr)
                    {
                        // TODO should this be realName?
                        QString funcName = ("vmt." + className + "." + method.name);

                        // figure out the highest-level class that defines the function
                        for (auto baseClass : baseClasses)
                            for (auto parentMethod : core->getAnalysisClassMethods(baseClass.className))
                                if (parentMethod.addr == method.addr)
                                    // handle by processing parent
                                    goto skip;

                        ++methodDefinitionsCreated;

                        // Using this MASSIVELY increases performance cost (single-threaded analysis...)
                        if (analyseAddedFunctions)
                        {
                            //core->createFunctionAt(method.addr, funcName);
                            if(useAnalysisFunctionAdd)
                                // This is *also* crazy slow (probably N^2? + single-threaded analysis...)
                                rz_core_analysis_function_add(rizinCore, funcName.toStdString().c_str(), method.addr, recursiveAnalysis);
                            else
                                RzAnalysisFunctionAddNoUpdate(rizinCore, funcName.toStdString().c_str(), method.addr, propagateNoreturn, recursiveAnalysis);
                        }
                        else
                        {
                            //char* name = (char*)(new std::string(funcName.toStdString()))->c_str();
                            RzAnalysisFunction* funcDef = rz_analysis_create_function(rizinCore->analysis, funcName.toStdString().c_str(), method.addr, RzAnalysisFcnType::RZ_ANALYSIS_FCN_TYPE_ANY);
                        }
                        skip:
                        ;
                    }
                    // if we've already made a definition, but it hasn't been analysed, and analysis is enabled, trigger analysis
                    else if (analyseAddedFunctions && core->functionAt(method.addr)->ninstr == 0)
                    {
                        // backup name
                        std::string funcName = core->functionAt(method.addr)->name;
                        // recreate
                        rz_analysis_function_delete(core->functionAt(method.addr));
                        if (useAnalysisFunctionAdd)
                            rz_core_analysis_function_add(rizinCore, funcName.c_str(), method.addr, recursiveAnalysis);
                        else
                            RzAnalysisFunctionAddNoUpdate(rizinCore, funcName.c_str(), method.addr, propagateNoreturn, recursiveAnalysis);
                    }
                }
            }
        }
    }

    // if we're using our bootleg analysis code, we almost certainly skipped this call
    if(analyseAddedFunctions && !useAnalysisFunctionAdd)
        rz_core_analysis_flag_every_function(rizinCore);

    core->functionsChanged();
    core->flagsChanged();
    core->message("VirtualTaggerPlugin: " + QString::number(classNames.size()) + " classes");
    core->message("VirtualTaggerPlugin: " + QString::number(methodDefinitionsCreated) + " method definitions created");
    core->message("VirtualTaggerPlugin: " + QString::number(stringsRemoved) + " strings removed");
    core->message("VirtualTaggerPlugin: " + QString::number(vtableXrefsCreated) + " X-Refs created");
    core->message("VirtualTaggerPlugin: Finished tagging in " + QString::number(timer.elapsed() / 1000.0) + "s");
}

void VirtualTaggerPluginWidget::on_checkboxClicked(bool checked)
{
    QWidget* widget = qobject_cast<QWidget*>(sender());
    settings.insert(widget->property("setting").toString(), checked);
}

void VirtualTaggerPluginWidget::on_runTaggerButtonClicked()
{
    runTagger(settings);
}

void VirtualTaggerPluginWidget::on_saveSettingsButtonClicked()
{
    QSettings settingsOut("BFrizzleFoShizzle", "VirtualTaggerPlugin");
    for (auto key : settings.keys())
    {
        settingsOut.setValue(key, settings.value(key));
    }
}

QCheckBox* VirtualTaggerPluginWidget::addSetting(QString setting, QString label, QString tooltip, QLayout* layout, QWidget* parent)
{
    QCheckBox* checkbox = new QCheckBox(label, parent);
    checkbox->setChecked(settings.value(setting));
    checkbox->setFont(Config()->getFont());
    checkbox->setToolTip(tooltip);
    checkbox->setProperty("setting", setting);
    connect(checkbox, &QCheckBox::clicked, this, &VirtualTaggerPluginWidget::on_checkboxClicked);
    layout->addWidget(checkbox);

    return checkbox;
}

void VirtualTaggerPluginWidget::on_generateFunctionEntriesClicked(bool checked)
{
    if (checked)
    {
        analyseAddedFunctionsCheck->setDisabled(false);
        recursiveAnalysisCheck->setDisabled(!analyseAddedFunctionsCheck->isChecked());
        useAnalysisFunctionAddCheck->setDisabled(!analyseAddedFunctionsCheck->isChecked());
        propagateNoreturnCheck->setDisabled(!analyseAddedFunctionsCheck->isChecked() || useAnalysisFunctionAddCheck->isChecked());
    }
    else
    {
        analyseAddedFunctionsCheck->setDisabled(true);
        recursiveAnalysisCheck->setDisabled(true);
        useAnalysisFunctionAddCheck->setDisabled(true);
        propagateNoreturnCheck->setDisabled(true);
    }
}

void VirtualTaggerPluginWidget::on_analyseAddedFunctionsClicked(bool checked)
{
    if (checked)
    {
        recursiveAnalysisCheck->setDisabled(false);
        useAnalysisFunctionAddCheck->setDisabled(false);
        propagateNoreturnCheck->setDisabled(useAnalysisFunctionAddCheck->isChecked());
    }
    else
    {
        recursiveAnalysisCheck->setDisabled(true);
        useAnalysisFunctionAddCheck->setDisabled(true);
        propagateNoreturnCheck->setDisabled(true);
    }
}

void VirtualTaggerPluginWidget::on_useAnalysisFunctionClicked(bool checked)
{
    if (checked)
    {
        propagateNoreturnCheck->setDisabled(true);
    }
    else
    {
        propagateNoreturnCheck->setDisabled(false);
    }
}

VirtualTaggerPluginWidget::VirtualTaggerPluginWidget(MainWindow* main) : CutterDockWidget(main)
{
    // read settings
    QSettings settingsIn("BFrizzleFoShizzle", "VirtualTaggerPlugin");
    for (auto setting : settingsIn.allKeys())
        settings.insert(setting, settingsIn.value(setting).toBool());

    this->setObjectName("VirtualTaggerPluginWidget");
    this->setWindowTitle("Virtual Tagger");

    QWidget* content = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(content);
    content->setLayout(layout);
    this->setWidget(content);

    QLabel* text = new QLabel(content);
    text->setFont(Config()->getFont());
    text->setText("Virtual Tagger settings:");
    layout->addWidget(text);

    addSetting(GENERATE_X_REFS_SETTING, "Generate X-Refs", "Generates X-Refs from vtable slot -> function", layout, content);
    addSetting(CLEAR_STRINGS_SETTING, "Clear strings in vtables", "Removes string detections that occur inside vtable pointers", layout, content);
    addSetting(SET_DATA_SETTING, "Set vtable entries to data", "Sets each vtable method entry to data so Cutter interprets it as a pointer", layout, content);
    addSetting(TAG_PURE_VIRTUALS_SETTING, "Tag pure virtuals", "Runs the tagger on \"pure virtual\" functions (or any detected vtable offsets that don't have class method entries)", layout, content);
    addSetting(ADD_NAME_COMMENT, "Add function name comments", "Adds a comment to each vtable entry with the name of the function it points to, making it easier to read X-Refs", layout, content);
    QCheckBox* generateFunctionEntriesCheck = addSetting(GENERATE_FUNCTION_ENTRIES, "Generate function entries", "Generates function definitions so they show up in the functions panel", layout, content);
    analyseAddedFunctionsCheck = addSetting(ANALYSE_ADDED_FUNCTIONS, "Analyse added functions", "Runs analysis on virtual functions."
        "\nFunction analysis can be enabled + run after generating function entries, but can only be run ONCE."
        "\nIf this is disabled, only the first instruction of a method will be associated with it's definition", layout, content);
    recursiveAnalysisCheck = addSetting(RECURSIVE_ANALYSIS, "Recursive analyisis", "Enables recursive function analysis."
        "\nMust be enabled before first Virtual Tagger analysis in order to work.", layout, content);
    useAnalysisFunctionAddCheck = addSetting(USE_ANALYSIS_FUNCTION_ADD, "Use analysis_function_add (slow) (not commonly needed)"
        , "Only enable this if you get weird results with it disabled."
        "\nIf this is disabled, Virtual Tagger uses a custom faster analysis implementation that is *almost* equivalent to the internal function Cutter uses: rz_core_analysis_function_add"
        "\nIf this is enabled, rz_core_analysis_function_add will be used (which can be multiple orders of magnitude slower - can take 10+ minutes to run for some binaries)"
        "\nMust be enabled before first Virtual Tagger analysis in order to work.", layout, content);
    propagateNoreturnCheck = addSetting(PROPAGATE_NORETURN, "Propagate noreturn (slow) (not commonly needed)", "if you don't know if you need this, you don't need it."
        "\nEnables propagation of noreturn flags."
        "\nThis usually increases analysis time by over 10x."
        "\nanalysis_function_add always has this enabled."
        "\nMust be enabled before first Virtual Tagger analysis in order to work.", layout, content);

    QPushButton* saveButton = new QPushButton(content);
    saveButton->setText("Save settings");
    saveButton->setFont(Config()->getFont());
    saveButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
    saveButton->setMaximumHeight(30);
    layout->addWidget(saveButton, 1);
    connect(saveButton, &QPushButton::clicked, this, &VirtualTaggerPluginWidget::on_saveSettingsButtonClicked);

    // this sets up initial checkbox state
    on_generateFunctionEntriesClicked(generateFunctionEntriesCheck->isChecked());

    // used to disable settings
    connect(generateFunctionEntriesCheck, &QCheckBox::clicked, this, &VirtualTaggerPluginWidget::on_generateFunctionEntriesClicked);
    connect(analyseAddedFunctionsCheck, &QCheckBox::clicked, this, &VirtualTaggerPluginWidget::on_analyseAddedFunctionsClicked);
    connect(useAnalysisFunctionAddCheck, &QCheckBox::clicked, this, &VirtualTaggerPluginWidget::on_useAnalysisFunctionClicked);

    layout->addStretch();

    QPushButton* runTaggerButton = new QPushButton(content);
    runTaggerButton->setText("Force run virtual tagger");
    runTaggerButton->setFont(Config()->getFont());
    runTaggerButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
    runTaggerButton->setMaximumHeight(50);
    layout->addWidget(runTaggerButton, 1);
    layout->setAlignment(runTaggerButton, Qt::AlignHCenter);
    connect(runTaggerButton, &QPushButton::clicked, this, &VirtualTaggerPluginWidget::on_runTaggerButtonClicked);

    QMetaObject::Connection con1 = connect(Core(), &CutterCore::refreshAll, [this]()
        {
            runTagger(settings);
        });

    QAction* disassemblyAction = main->getContextMenuExtensions(MainWindow::ContextMenuType::Disassembly)->addAction("Force run virtual tagger");
    QMetaObject::Connection con2 = connect(disassemblyAction, &QAction::triggered, [this]()
        {
            runTagger(settings);
        });

    if (!con1 || !con2)
        Core()->message("VirtualTaggerPlugin: Connection failed");
}

void VirtualTaggerPlugin::setupInterface(MainWindow *main)
{
    QSettings settings("BFrizzleFoShizzle","VirtualTaggerPlugin");

    // default settings
    if (!settings.contains(GENERATE_X_REFS_SETTING))
        settings.setValue(GENERATE_X_REFS_SETTING, true);
    if (!settings.contains(CLEAR_STRINGS_SETTING))
        settings.setValue(CLEAR_STRINGS_SETTING, true);
    if (!settings.contains(SET_DATA_SETTING))
        settings.setValue(SET_DATA_SETTING, true);
    if (!settings.contains(TAG_PURE_VIRTUALS_SETTING))
        settings.setValue(TAG_PURE_VIRTUALS_SETTING, true);
    if (!settings.contains(ADD_NAME_COMMENT))
        settings.setValue(ADD_NAME_COMMENT, true);
    if (!settings.contains(GENERATE_FUNCTION_ENTRIES))
        settings.setValue(GENERATE_FUNCTION_ENTRIES, true);
    if (!settings.contains(ANALYSE_ADDED_FUNCTIONS))
        settings.setValue(ANALYSE_ADDED_FUNCTIONS, false);
    if (!settings.contains(PROPAGATE_NORETURN))
        settings.setValue(PROPAGATE_NORETURN, false);
    if (!settings.contains(RECURSIVE_ANALYSIS))
        settings.setValue(RECURSIVE_ANALYSIS, false);

    settings.sync();

    VirtualTaggerPluginWidget* widget = new VirtualTaggerPluginWidget(main);
    main->addPluginDockWidget(widget);
}
