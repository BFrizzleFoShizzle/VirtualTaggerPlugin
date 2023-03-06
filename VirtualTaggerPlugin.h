#ifndef VIRTUALTAGGERPLUGIN_H
#define VIRTUALTAGGERPLUGIN_H

#include <CutterPlugin.h>

// Adapted from "SamplePlugin" examples from the Cutter repo (GPLv3)

class VirtualTaggerPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "re.rizin.cutter.plugins.CutterPlugin")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;

    QString getName() const override { return "Virtual Tagger Plugin"; }
    QString getAuthor() const override { return "Bryden Frizzell"; }
    QString getDescription() const override { return "A plugin for automatically tagging virtual functions with their class name + slot index."; }
    QString getVersion() const override { return "1.0"; }

};

#endif // VIRTUALTAGGERPLUGIN_H
