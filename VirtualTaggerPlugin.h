#ifndef VIRTUALTAGGERPLUGIN_H
#define VIRTUALTAGGERPLUGIN_H

#include <CutterPlugin.h>
#include <QLabel>
#include <QCheckBox>
#include <QHash>

// Adapted from "SamplePlugin" examples from the Cutter repo (GPLv3)

typedef QHash<QString, bool> SettingsMap;

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

class VirtualTaggerPluginWidget : public CutterDockWidget
{
    Q_OBJECT

public:
    explicit VirtualTaggerPluginWidget(MainWindow* main);

private:
    QCheckBox* addSetting(QString setting, QString label, QString tooltip, QLayout* layout, QWidget* parent);
    QCheckBox* analyseAddedFunctionsCheck;
    QCheckBox* recursiveAnalysisCheck;
    QCheckBox* useAnalysisFunctionAddCheck;
    QCheckBox* propagateNoreturnCheck;
    // pointer to prevent destructor from triggering - we want to trigger saving manually
    SettingsMap settings;

private slots:
    void on_checkboxClicked(bool checked);
    void on_generateFunctionEntriesClicked(bool checked);
    void on_analyseAddedFunctionsClicked(bool checked);
    void on_useAnalysisFunctionClicked(bool checked);
    void on_saveSettingsButtonClicked();
    void on_runTaggerButtonClicked();
};


#endif // VIRTUALTAGGERPLUGIN_H
