'''
Take the manifest files and build files for Enterprise Security
'''
import glob
import os.path
import json
import argparse
# HIGH Level Fields

# Add these lines:
import nltk
from nltk.corpus import stopwords
import enchant
import grammar_check

stop_words_en = set(stopwords.words('english'))


def check_spelling(sentences):
    errors = []
    sp = enchant.Dict("en_US")
    words = nltk.word_tokenize(sentences)
    words = [word for word in words if word.isalpha()]
    for word in words:
        if not sp.check(word):
            errors.append("\"%s\" not recognized" % word)

    return errors


def check_grammar(sentences):
    errors = []
    grammar_tool = grammar_check.LanguageTool('en-US')
    grammar_tool.disabled.add("EN_QUOTES")
    grammar_tool.disabled.add("THREE_NN")
    grammar_tool.disabled.add("NON3PRS_VERB")
    grammar_tool.disabled.add("MASS_AGREEMENT")
    grammar_tool.disabled.add("EN_UNPAIRED_BRACKETS")
    grammar_tool.disabled.add("THIS_NNS")
    grammar_tool.disabled.add("MUCH_COUNTABLE")
    grammar_tool.disabled.add("COMMA_PARENTHESIS_WHITESPACE")
    grammar_errors = grammar_tool.check(sentences)
    for grammar_error in grammar_errors:
        errors.append(grammar_error)

    return errors


def spell_check_search_manifest(search):
    ''' Validate that the search has the required fields for savedsearches.conf '''
    errors = []

    spelling_errors = check_spelling(search['search_name'])
    errors.extend(spelling_errors)

    spelling_errors = check_spelling(search['search_description'])
    grammar_errors = check_grammar(search['search_description'])
    errors.extend(spelling_errors)
    errors.extend(grammar_errors)

    if 'how_to_implement' in search:
        spelling_errors = check_spelling(search['how_to_implement'])
        grammar_errors = check_grammar(search['how_to_implement'])
        errors.extend(spelling_errors)
        errors.extend(grammar_errors)

    if 'eli5' in search:
        spelling_errors = check_spelling(search['eli5'])
        grammar_errors = check_grammar(search['eli5'])
        errors.extend(spelling_errors)
        errors.extend(grammar_errors)

    if 'known_false_positives' in search:
        search['known_false_positives'].encode('ascii')
        spelling_errors = check_spelling(search['known_false_positives'])

    if 'correlation_rule' in search and 'notable' in search['correlation_rule']:
        spelling_errors = check_spelling(search['correlation_rule']['notable']['rule_title'])
        errors.extend(spelling_errors)

        spelling_errors = check_spelling(search['correlation_rule']['notable']['rule_description'])
        errors.extend(spelling_errors)

    return errors


def spell_check_story_manifest(story):
    ''' Validate that the analytic story manifest is in the proper format '''

    errors = []

    spelling_errors = check_spelling(story['name'])
    errors.extend(spelling_errors)

    spelling_errors = check_spelling(story['description'])
    grammar_errors = check_grammar(story['description'])
    errors.extend(spelling_errors)
    errors.extend(grammar_errors)

    spelling_errors = check_spelling(story['narrative'])
    grammar_errors = check_grammar(story['narrative'])
    errors.extend(spelling_errors)
    errors.extend(grammar_errors)


def main():
    ''' Open manifest file, validate required fields '''

    errors = False
    story_manifest_files = os.path.join(MANIFEST_DIRECTORY, "*/stories/*.json")
    stories_checked = 0
    for story_manifest_file in glob.glob(story_manifest_files):
        try:
            story_manifest_data = json.loads(open(story_manifest_file, 'r').read())
        except Exception as e:
            print "Error reading %s" % story_manifest_file
            errors = True
            continue

        stories_checked += 1
        story_errors = spell_check_story_manifest(story_manifest_data)
        if story_errors:
            errors = True
            for err in story_errors:
                print os.path.basename(story_manifest_file)
                print "\t%s" % err

    search_manifest_files = os.path.join(MANIFEST_DIRECTORY, "*/searches/*.json")
    searches_checked = 0
    for search_manifest_file in glob.glob(search_manifest_files):
        try:
            search_manifest_data = json.loads(open(search_manifest_file, 'r').read())
        except Exception as e:
            errors = True
            print "Error reading %s" % search_manifest_file
            print e
            continue

        searches_checked += 1
        sm_errors = spell_check_search_manifest(search_manifest_data)
        if sm_errors:
            errors = True
            for err in sm_errors:
                print os.path.basename(search_manifest_file)
                print "\t%s" % err

    print "%d story manifests checked" % stories_checked
    print "%d search manifests checked" % searches_checked
    if not errors:
        print "No errors found"


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="spell checks the security-contents manifests")
    parser.add_argument("-p", "--path", required=True, help="path to security-security content repo")

    # parse them
    args = parser.parse_args()
    MANIFEST_DIRECTORY = args.path

    main()
