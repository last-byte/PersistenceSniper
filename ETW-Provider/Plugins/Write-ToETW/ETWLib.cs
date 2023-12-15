using System.Diagnostics.Tracing;
using System;

namespace PersistenceSniper.ETWLib
{
    [EventSource(Name = "PersistenceSniper", Guid = "4b22d928-e344-5d05-07b4-1b61c575912a")]
    public sealed class PersistenceSniperEventSource : EventSource
    {
        public static readonly PersistenceSniperEventSource Log = new PersistenceSniperEventSource();

        [Event(1001, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1001)]
        public void WriteRunAndRunOnce(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1001, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1002, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1002)]
        public void WriteImageFileExecutionOptions(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1002, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1003, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1003)]
        public void WriteNLDPDllOverridePath(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1003, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1004, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1004)]
        public void WriteAeDebug(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1004, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1005, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1005)]
        public void WriteWerFaultHangs(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1005, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1006, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1006)]
        public void WriteCmdAutoRun(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1006, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1007, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1007)]
        public void WriteExplorerLoad(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1007, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1008, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1008)]
        public void WriteWinlogonUserinit(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1008, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1009, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1009)]
        public void WriteWinlogonShell(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1009, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1010, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1010)]
        public void WriteTerminalProfileStartOnUserLogin(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1010, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1011, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1011)]
        public void WriteAppCertDlls(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1011, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1012, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1012)]
        public void WriteServiceDlls(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1012, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1013, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1013)]
        public void WriteGPExtensionDlls(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1013, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1014, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1014)]
        public void WriteWinlogonMPNotify(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1014, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1015, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1015)]
        public void WriteCHMHelperDll(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1015, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1016, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1016)]
        public void WriteHHCtrlHijacking(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1016, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1017, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1017)]
        public void WriteStartupPrograms(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1017, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1018, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1018)]
        public void WriteUserInitMprScript(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1018, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1019, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1019)]
        public void WriteAutodialDLL(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1019, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1020, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1020)]
        public void WriteLsaExtensions(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1020, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1021, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1021)]
        public void WriteServerLevelPluginDll(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1021, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1022, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1022)]
        public void WriteLsaPasswordFilter(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1022, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1023, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1023)]
        public void WriteLsaAuthenticationPackages(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1023, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1024, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1024)]
        public void WriteLsaSecurityPackages(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1024, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1025, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1025)]
        public void WriteWinlogonNotificationPackages(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1025, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1026, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1026)]
        public void WriteExplorerTools(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1026, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1027, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1027)]
        public void WriteDotNetDebugger(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1027, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1028, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1028)]
        public void WriteErrorHandlerCmd(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1028, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1029, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1029)]
        public void WriteWMIEventsSubscrition(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1029, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1030, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1030)]
        public void WriteWindowsServices(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1030, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1031, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1031)]
        public void WriteAppPaths(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1031, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1032, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1032)]
        public void WriteTerminalServicesInitialProgram(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1032, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1033, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1033)]
        public void WriteAccessibilityTools(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1033, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1034, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1034)]
        public void WriteAMSIProviders(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1034, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1035, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1035)]
        public void WritePowershellProfiles(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1035, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1036, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1036)]
        public void WriteSilentExitMonitor(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1036, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1037, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1037)]
        public void WriteTelemetryController(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1037, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1038, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1038)]
        public void WriteRDPWDSStartupPrograms(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1038, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1039, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1039)]
        public void WriteScheduledTasks(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1039, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1040, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1040)]
        public void WriteBitsJobsNotify(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1040, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1041, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1041)]
        public void WriteScreensaver(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1041, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1042, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1042)]
        public void WritePowerAutomate(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1042, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1043, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1043)]
        public void WriteOfficeAddinsAndTemplates(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1043, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1044, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1044)]
        public void WriteServices(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1044, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1045, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1045)]
        public void WriteExplorerContextMenu(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1045, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1046, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1046)]
        public void WriteServiceControlManagerSD(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1046, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1047, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1047)]
        public void WriteOfficeAiHijacking(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1047, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1048, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1048)]
        public void WriteRunExAndRunOnceEx(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1048, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1049, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1049)]
        public void WriteDotNetStartupHooks(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1049, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1050, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1050)]
        public void WriteRIDHijacking(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1050, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1051, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1051)]
        public void WriteSubornerAttack(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1051, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

        [Event(1052, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = (EventTask)1052)]
        public void WriteDSRMBackdoor(string message, string technique, string classification, string path, string values, string accessGained, string note, string reference, string signature, string isBuiltinBinary, string isLolbin, string vtEntries)
        {
            WriteEvent(1052, new object[] { message, technique, classification, path, values, accessGained, note, reference, signature, isBuiltinBinary, isLolbin, vtEntries });
        }

    }
}
