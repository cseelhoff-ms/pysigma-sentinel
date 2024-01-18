import pytest
from sigma.collection import SigmaCollection

from sigma.backends.azure import AzureBackend
from sigma.pipelines.azure import azure_windows_pipeline
from sigma.pipelines.azure.azure import azure_windows_service_map


@pytest.mark.parametrize(
    ("service", "source"),
    azure_windows_service_map.items()
)
def test_splunk_windows_pipeline_simple(service, source):
    assert AzureBackend(processing_pipeline=azure_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: {service}
            detection:
                sel:
                    EventID: 123
                    field: value
                condition: sel
        """)
    ) == [f'{source}\n| where (EventID =~ 123 and field =~ "value")']


def test_azure_process_creation():
    assert AzureBackend(processing_pipeline=azure_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_img:
                    - Image|endswith: '\addinutil.exe'
                    - Description|contains: '7-Zip'
                    - OriginalFileName: 'AddInUtil.exe'
                    - ParentImage|endswith: '\addinutil.exe'
                    - ParentCommandLine: 'C:\\WINDOWS\\system32\\\*.bat'
                selection_susp_1_flags:
                    CommandLine|contains:
                        - '-AddInRoot:'
                        - '-PipelineRoot:'
                selection_susp_1_paths:
                    CommandLine|contains:
                        - '\AppData\Local\Temp\'
                        - '\Desktop\'
                        - '\Downloads\'
                        - '\Users\Public\'
                        - '\Windows\Temp\'
                selection_susp_2:
                    CommandLine|contains:
                        - '-AddInRoot:.'
                        - '-PipelineRoot:"."'
                    CurrentDirectory|contains:
                        - '\AppData\Local\Temp\'
                        - '\Desktop\'
                        - '\Downloads\'
                        - '\Users\Public\'
                        - '\Windows\Temp\'
                    IntegrityLevel: System
                    User|contains: # covers many language settings
                        - 'AUTHORI'
                        - 'AUTORI'
                filter:
                    CommandLine|contains|all:
                        - '\Windows\TEMP\'
                        - '.exe'
                condition: selection_img and (all of selection_susp_1_* or selection_susp_2) and not filter
        """)
    ) == [
    '_Im_ProcessCreate (' +
    'commandline_has_any = dynamic([' + 
    """
    '-AddInRoot:', '-PipelineRoot:', '-AddInRoot:.', '-PipelineRoot:"."'
    """ +
    '])' +
    ', actingprocess_has_any = dynamic([' +
    """
    """ +
    '])' +
    ', targetprocess_has_any = dynamic([' +
    """
    """ +
    '])' +
    ', parentprocess_has_any = dynamic([' +
    """ +
    '])' +
    ', eventtype = ProcessCreated'
    #SecurityEvent\n| where EventID =~ "4688" and ((
    # CommandLine =~ "test" and 
    # CurrentDirectory =~ "test" and 
    # Image =~ "test" and 
    # IntegrityLevel =~ "test" and 
    # ParentCommandLine =~ "test" and 
    # ParentImage =~ "test" and 
    # ParentProcessGuid =~ "test" and 
    # ParentProcessId =~ "test" and 
    # ProcessGuid =~ "test" and 
    # ProcessId =~ "test" and 
    # User =~ "test"))
