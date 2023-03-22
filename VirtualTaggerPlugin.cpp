#include "VirtualTaggerPlugin.h"

#include <MainWindow.h>

#include <qapplication.h>
#include <qclipboard.h>
#include <qelapsedtimer.h>

#include <fstream>

#include <thread>
#include <mutex>

// Adapted from "SamplePlugin" examples from the Cutter repo (GPLv3)

void VirtualTaggerPlugin::setupPlugin() {}

std::mutex mutex;

static void updateClassNames()
{
    std::lock_guard<std::mutex> lock(mutex);

    auto core = Core();
    auto rizinCore = core->core();

    QElapsedTimer timer;
    timer.start();

    // core->getArchBits() seems to return byte size of pointer? Probably a bug?
    // Rizin gives the correct size, so I'm using that in case Cutter's API changes
    size_t pointerSize = rz_bin_object_get_info(rz_bin_cur_object(rizinCore->bin))->bits / 8;
    //core->message("Bits: " + QString::number(core->getArchBits()) + " bytes: " + QString::number(pointerSize));
    auto classNames = core->getAllAnalysisClasses(false);
    core->message("VirtualTaggerPlugin: " + QString::number(classNames.size()) + " classes");

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
                    // Clean up vtable entry
                    // Cutter often misinterprets vtable entries as strings, 
                    // which also messes up Cutter's interpretation after setting to data
                    for (int j = 0; j < pointerSize; ++j)
                    {
                        size_t addr = vtableEntryAddr + j;
                        core->removeString(addr);
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
                                core->delFlag(flag);
                                ++stringsRemoved;
                            }
                        }
                    }
                    core->setToData(vtableEntryAddr, pointerSize);

                    // add X-ref to vtable entry
                    rz_analysis_xrefs_set(rizinCore->analysis, vtableEntryAddr, method.addr, RzAnalysisXRefType::RZ_ANALYSIS_XREF_TYPE_DATA);
                    ++vtableXrefsCreated;
                     
                    // add comment to make reading x-refs easier
                    // Cutter's API is slow, so we set the comment directly via Rizin (sketchy but works since we run early)
                    //core->setComment(vtableEntryAddr, className + "." + method.name);
                    rz_meta_set_string(rizinCore->analysis, RZ_META_TYPE_COMMENT, vtableEntryAddr, (className + "." + method.name).toStdString().c_str());
                }

                // update for next loop
                nextOffset = classVTables[0].addr + method.vtableOffset + pointerSize;

                // create function definitions
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

                    // Using this MASSIVELY increases performance cost (single-threaded analysis...)
                    //core->createFunctionAt(method.addr, funcName);
                    // This is *also* crazy slow (single-threaded analysis...)
                    //rz_core_analysis_function_add(rizinCore, funcName.toStdString().c_str(), method.addr, false);

                    //char* name = (char*)(new std::string(funcName.toStdString()))->c_str();
                    RzAnalysisFunction* funcDef = rz_analysis_create_function(rizinCore->analysis, funcName.toStdString().c_str(), method.addr, RzAnalysisFcnType::RZ_ANALYSIS_FCN_TYPE_ANY);
                    ++methodDefinitionsCreated;

                skip:
                    ;
                }
            }
        }
    }

    core->functionsChanged();
    core->flagsChanged();
    core->message("VirtualTaggerPlugin: " + QString::number(methodDefinitionsCreated) + " method definitions created");
    core->message("VirtualTaggerPlugin: " + QString::number(stringsRemoved) + " strings removed");
    core->message("VirtualTaggerPlugin: " + QString::number(vtableXrefsCreated) + " X-Refs created");
    core->message("VirtualTaggerPlugin: Finished tagging in " + QString::number(timer.elapsed() / 1000.0) + "s");
}

void VirtualTaggerPlugin::setupInterface(MainWindow *main)
{

    //QMetaObject::Connection con1 = connect(main, &MainWindow::finalizeOpen, this, [this]()
    QMetaObject::Connection con1 = connect(Core(), &CutterCore::refreshAll, []()
    {
        updateClassNames();
    });

    QAction* disassemblyAction = main->getContextMenuExtensions(MainWindow::ContextMenuType::Disassembly)->addAction("Force run virtual tagger");
    QMetaObject::Connection con2 = connect(disassemblyAction, &QAction::triggered, []()
    {
        updateClassNames();
    });

    if (!con1 || !con2)
        Core()->message("VirtualTaggerPlugin: Connection failed");
}
