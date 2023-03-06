#include "VirtualTaggerPlugin.h"

#include <MainWindow.h>

#include <qapplication.h>
#include <qclipboard.h>

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
    auto classNames = core->getAllAnalysisClasses(false);
    core->message("VirtualTaggerPlugin: " + QString::number(classNames.size()) + " classes");

    for (auto className : classNames)
    {
        // TODO multiple use
        // update name
        auto methods = core->getAnalysisClassMethods(className);
        auto baseClasses = core->getAnalysisClassBaseClasses(className);

        methodloop:
        for (auto method : methods)
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

                // Using this MASSIVELY increases performance cost (single-threaded analysis...)
                //core->createFunctionAt(method.addr, funcName);
                // This is *also* crazy slow (single-threaded analysis...)
                //rz_core_analysis_function_add(rizinCore, funcName.toStdString().c_str(), method.addr, false);

                //char* name = (char*)(new std::string(funcName.toStdString()))->c_str();
                RzAnalysisFunction* funcDef = rz_analysis_create_function(core->core()->analysis, funcName.toStdString().c_str(), method.addr, RzAnalysisFcnType::RZ_ANALYSIS_FCN_TYPE_ANY);

            skip:
                ;
            }
        }
    }

    core->functionsChanged();
    core->message("Finished renaming");
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
