# src/catlyst/config.py

from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).parent.parent.parent

# Load .env into os.environ immediately.
load_dotenv(PROJECT_ROOT / ".env")

# DeepVis Power Query column mappings and sort clause
DEEPVIS_COLUMN_MAPPINGS = [
    ("eventTime", "event.time"),
    ("agentUuid", "agent.uuid"),
    ("siteId", "site.id"),
    ("eventType", "event.type"),
    ("eventCategory", "event.category"),
    ("severity", "severity"),
    ("dataSourceCategory", "dataSource.category"),
    ("dataSourceName", "dataSource.name"),
    ("dataSourceVendor", "dataSource.vendor"),
    ("endpointOs", "endpoint.os"),
    ("endpointType", "endpoint.type"),
    ("osName", "os.name"),
    ("srcProcessChildProcCount", "src.process.childProcCount"),
    ("srcProcessCrossProcessCount", "src.process.crossProcessCount"),
    ("srcProcessCrossProcessDupRemoteProcessHandleCount", "src.process.crossProcessDupRemoteProcessHandleCount"),
    ("srcProcessCrossProcessDupThreadHandleCount", "src.process.crossProcessDupThreadHandleCount"),
    ("srcProcessCrossProcessOpenProcessCount", "src.process.crossProcessOpenProcessCount"),
    ("srcProcessCrossProcessOutOfStorylineCount", "src.process.crossProcessOutOfStorylineCount"),
    ("srcProcessCrossProcessThreadCreateCount", "src.process.crossProcessThreadCreateCount"),
    ("srcProcessModuleCount", "src.process.moduleCount"),
    ("srcProcessDnsCount", "src.process.dnsCount"),
    ("srcProcessNetConnCount", "src.process.netConnCount"),
    ("srcProcessNetConnInCount", "src.process.netConnInCount"),
    ("srcProcessNetConnOutCount", "src.process.netConnOutCount"),
    ("srcProcessRegistryChangeCount", "src.process.registryChangeCount"),
    ("srcProcessTgtFileCreationCount", "src.process.tgtFileCreationCount"),
    ("srcProcessTgtFileDeletionCount", "src.process.tgtFileDeletionCount"),
    ("srcProcessTgtFileModificationCount", "src.process.tgtFileModificationCount"),
    ("srcProcessIndicatorBootConfigurationUpdateCount", "src.process.indicatorBootConfigurationUpdateCount"),
    ("srcProcessIndicatorEvasionCount", "src.process.indicatorEvasionCount"),
    ("srcProcessIndicatorExploitationCount", "src.process.indicatorExploitationCount"),
    ("srcProcessIndicatorGeneralCount", "src.process.indicatorGeneralCount"),
    ("srcProcessIndicatorInfostealerCount", "src.process.indicatorInfostealerCount"),
    ("srcProcessIndicatorInjectionCount", "src.process.indicatorInjectionCount"),
    ("srcProcessIndicatorPersistenceCount", "src.process.indicatorPersistenceCount"),
    ("srcProcessIndicatorPostExploitationCount", "src.process.indicatorPostExploitationCount"),
    ("srcProcessIndicatorRansomwareCount", "src.process.indicatorRansomwareCount"),
    ("srcProcessIndicatorReconnaissanceCount", "src.process.indicatorReconnaissanceCount"),
    ("srcProcessIntegrityLevel", "src.process.integrityLevel"),
    ("srcProcessIsNative64Bit", "src.process.isNative64Bit"),
    ("srcProcessIsRedirectCmdProcessor", "src.process.isRedirectCmdProcessor"),
    ("srcProcessIsStorylineRoot", "src.process.isStorylineRoot"),
    ("srcProcessSignedStatus", "src.process.signedStatus"),
    ("srcProcessVerifiedStatus", "src.process.verifiedStatus"),
    ("tgtFileExtension", "tgt.file.extension"),
    ("tgtFileIsExecutable", "tgt.file.isExecutable"),
    ("tgtFileType", "tgt.file.type"),
    ("tgtFileSize", "tgt.file.size"),
    ("srcPortNumber", "src.port.number"),
    ("dstPortNumber", "dst.port.number"),
    ("eventNetworkDirection", "event.network.direction"),
    ("eventNetworkProtocolName", "event.network.protocolName"),
    ("eventNetworkConnectionStatus", "event.network.connectionStatus"),
    ("eventDnsProtocol", "event.dns.protocol"),
    ("eventDnsResponseCode", "event.dns.responseCode"),
    ("eventLoginIsAdministratorEquivalent", "event.login.isAdministratorEquivalent"),
    ("eventLoginLoginIsSuccessful", "event.login.loginIsSuccessful"),
    ("eventLoginType", "event.login.type"),
]

DEEPVIS_SORT_CLAUSE = " | sort by event.time desc"
