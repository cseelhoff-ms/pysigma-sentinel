from typing import List
from sigma.collection import SigmaCollection
from sigma.backends.azure import AzureBackend
from sigma.pipelines.azure import azure_windows_pipeline
from sigma.rule import SigmaRule
from datetime import date
from sigma.parser.modifiers import SigmaRuleTag

with open('template.json', 'r') as f:
    templateContents = f.read()

backend: AzureBackend = AzureBackend(processing_pipeline=azure_windows_pipeline())
procCollection: SigmaCollection = SigmaCollection.load_ruleset(['./process_creation/'])
sigmaRules: List[SigmaRule] = procCollection.rules
for sigmaRule in sigmaRules:
    author: str = sigmaRule.author if sigmaRule.author is not None else ""
    description: str = sigmaRule.description if sigmaRule.description is not None else ""
    falsepositives: List[str] = sigmaRule.falsepositives
    ruleid: str = str(sigmaRule.id)
    level: str = str(sigmaRule.level)
    #date_modified: date = sigmaRule.modified
    references: List[str] = sigmaRule.references
    sourceURL: str = str(sigmaRule.source.path)
    status: str = str(sigmaRule.status)
    description += ' Author: ' + author + ' False Positives: ' + falsepositives.join(', ') + ' References: ' + references.join(', ') + ' Source URL: ' + sourceURL + ' Status: ' + status
    title: str = sigmaRule.title
    tags: List[str] = []
    tactics: List[str] = []
    techniques: List[str] = []
    sigmaTags: List[SigmaRuleTag] = sigmaRule.tags
    for tag in sigmaTags:
        tags.append(tag.namespace + ':' + tag.name)
        tactics.append(tag.namespace)
        techniques.append(tag.name)
    
    convertedStrings: List[str] = backend.convert_rule(sigmaRule)
    #for convertedString in convertedStrings:
    #    print(convertedString)
    query = convertedStrings[0]
    #query = query.replace('\\\\', '\\')
    #query = query.replace('\\\"', '\"')
    #query = query.replace('\"', '\\\"')
    #query = query.replace('\n', '')
    #query = query.replace('\r', '')
    #query = query.replace('\t', '')
    #query = query.replace('  ', '')
    newTemplate: str = templateContents.replace('---RULEID---', ruleid).replace('---TITLE---', title).replace('---DESCRIPTION---', description).replace('---LEVEL---', level).replace('---QUERY---', query)
    #write newTemplate to file
    with open('./output/' + ruleid + '.json', 'w') as f:
        f.write(newTemplate)

