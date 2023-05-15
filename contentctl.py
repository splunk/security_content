import sys
import argparse
import os

from bin.contentctl_project.contentctl_core.domain.entities.link_validator import LinkValidator

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'bin/contentctl_project')))

from bin.contentctl_project.contentctl_core.application.use_cases.content_changer import ContentChanger, ContentChangerInputDto
from bin.contentctl_project.contentctl_core.application.use_cases.generate import GenerateInputDto, Generate
from bin.contentctl_project.contentctl_core.application.use_cases.validate import ValidateInputDto, Validate
from bin.contentctl_project.contentctl_core.application.use_cases.doc_gen import DocGenInputDto, DocGen
from bin.contentctl_project.contentctl_core.application.use_cases.new_content import NewContentInputDto, NewContent, NewAttackDataContent
from bin.contentctl_project.contentctl_core.application.use_cases.reporting import ReportingInputDto, Reporting
from bin.contentctl_project.contentctl_core.application.use_cases.convert import ConvertInputDto, Convert
from bin.contentctl_project.contentctl_core.application.use_cases.initialize import Initialize
from bin.contentctl_project.contentctl_core.application.use_cases.deploy import Deploy
from bin.contentctl_project.contentctl_core.application.use_cases.build import Build
from bin.contentctl_project.contentctl_core.application.use_cases.inspect import Inspect
from bin.contentctl_project.contentctl_core.application.factory.factory import FactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.ba_factory import BAFactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.new_content_factory import NewContentFactoryInputDto
from bin.contentctl_project.contentctl_core.application.factory.object_factory import ObjectFactoryInputDto
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from bin.contentctl_project.contentctl_infrastructure.builder.sigma_converter import SigmaConverterInputDto
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_json_adapter import ObjToJsonAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_story_builder import SecurityContentStoryBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_detection_builder import SecurityContentDetectionBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_basic_builder import SecurityContentBasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_investigation_builder import SecurityContentInvestigationBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_baseline_builder import SecurityContentBaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.security_content_playbook_builder import SecurityContentPlaybookBuilder
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct, SigmaConverterTarget
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_conf_adapter import ObjToConfAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_md_adapter import ObjToMdAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_svg_adapter import ObjToSvgAdapter
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_attack_nav_adapter import ObjToAttackNavAdapter
from bin.contentctl_project.contentctl_infrastructure.builder.attack_enrichment import AttackEnrichment
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.adapter.obj_to_attackdata_yml_adapter import ObjToAttackDataYmlAdapter

def init():

    print("""
Running Splunk Security Content Control Tool (contentctl)
starting program loaded for TIE Fighter...
      _                                            _
     T T                                          T T
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                   ____                   | |
     | |            ___.r-"`--'"-r.____           | |
     | |.-._,.,---~"_/_/  .----.  \_\_"~---,.,_,-.| |
     | ]|.[_]_ T~T[_.-Y  / \  / \  Y-._]T~T _[_].|| |
    [|-+[  ___]| [__  |-=[--()--]=-|  __] |[___  ]+-|]
     | ]|"[_]  l_j[_"-l  \ /  \ /  !-"_]l_j  [_]~|| |
     | |`-' "~"---.,_\\"\  "o--o"  /"/_,.---"~" `-'| |
     | |             ~~"^-.____.-^"~~             | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     | |                                          | |
     l_i                                          l_j -Row

    """)


def content_changer(args) -> None:
    factory_input_dto = ObjectFactoryInputDto(
        os.path.abspath(args.path),
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    input_dto = ContentChangerInputDto(
        ObjToYmlAdapter(args.path),
        factory_input_dto,
        args.change_function
    )

    content_changer = ContentChanger()
    content_changer.execute(input_dto)


def generate(args) -> None:
    if not args.product:
        print("ERROR: missing parameter -p/--product .")
        sys.exit(1)

    if args.product not in ['ESCU', 'SSA', 'API']:
        print("ERROR: invalid product. valid products are ESCU, SSA or API. ")
        sys.exit(1)


    if args.cached_and_offline:
        LinkValidator.initialize_cache(args.cached_and_offline)

    #Save runtime by only generating the required factory inputs
    factory_input_dto = None
    ba_factory_input_dto = None
    if args.product in ["ESCU", "API"]:

        factory_input_dto = FactoryInputDto(
            os.path.abspath(args.path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
            SecurityContentStoryBuilder(output_path=args.output),
            SecurityContentBaselineBuilder(),
            SecurityContentInvestigationBuilder(),
            SecurityContentPlaybookBuilder(input_path=args.path),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )
    if args.product in ["SSA", "API"]:
        ba_factory_input_dto = BAFactoryInputDto(
            os.path.abspath(args.path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline = args.cached_and_offline, skip_enrichment=args.skip_enrichment),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )


    if args.product == "ESCU":
        generate_input_dto = GenerateInputDto(
            os.path.abspath(args.output),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToConfAdapter(args.path),
            SecurityContentProduct.ESCU
        )
    elif args.product == "API":
        generate_input_dto = GenerateInputDto(
            os.path.abspath(args.output),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToJsonAdapter(),
            SecurityContentProduct.API
        )
    else:
        generate_input_dto = GenerateInputDto(
            os.path.abspath(args.output),
            factory_input_dto,
            ba_factory_input_dto,
            ObjToYmlAdapter(args.path),
            SecurityContentProduct.SSA
        )
    generate = Generate()
    generate.execute(generate_input_dto)

    if args.cached_and_offline:
        LinkValidator.close_cache()

def validate(args) -> None:
    if not args.product:
        print("ERROR: missing parameter -p/--product .")
        sys.exit(1)

    #For now, the custom product is treated just like ESCU
    if args.product == 'CUSTOM':
        args.product = 'ESCU'

    if args.product not in ['ESCU', 'SSA', 'all']:
        print("ERROR: invalid product. valid products are all, ESCU or SSA.  If you are building a custom app, use CUSTOM.")
        sys.exit(1)


    if args.cached_and_offline:
        LinkValidator.initialize_cache(args.cached_and_offline)

    #Save runtime by only generating the required factory inputs
    factory_input_dto = None
    ba_factory_input_dto = None
    if args.product in ["ESCU", "all"]:
        factory_input_dto = FactoryInputDto(
            os.path.abspath(args.path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, check_references=args.check_references, skip_enrichment=args.skip_enrichment),
            SecurityContentStoryBuilder(check_references=args.check_references),
            SecurityContentBaselineBuilder(check_references=args.check_references),
            SecurityContentInvestigationBuilder(check_references=args.check_references),
            SecurityContentPlaybookBuilder(input_path=args.path, check_references=args.check_references),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )
    if args.product in ["SSA", "all"]:
        ba_factory_input_dto = BAFactoryInputDto(
            os.path.abspath(args.path),
            SecurityContentBasicBuilder(),
            SecurityContentDetectionBuilder(force_cached_or_offline = args.cached_and_offline, check_references=args.check_references, skip_enrichment=args.skip_enrichment),
            SecurityContentDirector(),
            AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
        )

    if args.product == "ESCU" or args.product == "all":
        validate_input_dto = ValidateInputDto(
            factory_input_dto,
            ba_factory_input_dto,
            SecurityContentProduct.ESCU
        )
        validate = Validate()
        validate.execute(validate_input_dto)

    if args.product == "SSA" or args.product == "all":
        validate_input_dto = ValidateInputDto(
            factory_input_dto,
            ba_factory_input_dto,
            SecurityContentProduct.SSA
        )
        validate = Validate()
        validate.execute(validate_input_dto)

    if args.cached_and_offline:
        LinkValidator.close_cache()


def doc_gen(args) -> None:
    factory_input_dto = FactoryInputDto(
        os.path.abspath(args.path),
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
        SecurityContentStoryBuilder(),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentPlaybookBuilder(input_path=args.path),
        SecurityContentDirector(),
        AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
    )

    doc_gen_input_dto = DocGenInputDto(
        os.path.abspath(args.output),
        factory_input_dto,
        ObjToMdAdapter()
    )

    doc_gen = DocGen()
    doc_gen.execute(doc_gen_input_dto)


def new_content(args) -> None:
    if args.type == 'detection':
        contentType = SecurityContentType.detections
    elif args.type == 'story':
        contentType = SecurityContentType.stories
    elif args.type == 'attack_data':
        contentType = SecurityContentType.attack_data
    else:
        print("ERROR: type " + args.type + " not supported")
        sys.exit(1)


    new_content_factory_input_dto = NewContentFactoryInputDto(contentType)
    if args.type == 'attack_data':
        new_content_input_dto = NewContentInputDto(new_content_factory_input_dto, ObjToAttackDataYmlAdapter())
        new_content = NewAttackDataContent()
    else:
        new_content_input_dto = NewContentInputDto(new_content_factory_input_dto, ObjToYmlAdapter(args.path))
        new_content = NewContent()
    new_content.execute(new_content_input_dto)


def reporting(args) -> None:
    factory_input_dto = FactoryInputDto(
        os.path.abspath(args.path),
        SecurityContentBasicBuilder(),
        SecurityContentDetectionBuilder(force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment),
        SecurityContentStoryBuilder(),
        SecurityContentBaselineBuilder(),
        SecurityContentInvestigationBuilder(),
        SecurityContentPlaybookBuilder(input_path=args.path),
        SecurityContentDirector(),
        AttackEnrichment.get_attack_lookup(args.path, force_cached_or_offline=args.cached_and_offline, skip_enrichment=args.skip_enrichment)
    )

    reporting_input_dto = ReportingInputDto(
        factory_input_dto,
        ObjToSvgAdapter(),
        ObjToAttackNavAdapter()
    )

    reporting = Reporting()
    reporting.execute(reporting_input_dto)


def initialize(args) -> None:
    Initialize(args)


def build(args) -> None:
    Build(args)

def inspect(args) -> None:
    Inspect(args)

def cloud_deploy(args) -> None:
    Deploy(args)


def convert(args) -> None:
    if args.data_model == 'cim':
        data_model = SigmaConverterTarget.CIM
    elif args.data_model == 'raw':
        data_model = SigmaConverterTarget.RAW
    elif args.data_model == 'ocsf':
        data_model = SigmaConverterTarget.OCSF
    else:
        print("ERROR: data model " + args.data_model + " not supported")
        sys.exit(1)

    sigma_converter_input_dto = SigmaConverterInputDto(
        data_model = data_model,
        detection_path = args.detection_path,
        detection_folder = args.detection_folder, 
        input_path = args.path,
        log_source = args.log_source
    )

    convert_input_dto = ConvertInputDto(
        sigma_converter_input_dto = sigma_converter_input_dto,
        output_path = os.path.abspath(args.output)
    )
    convert = Convert()
    convert.execute(convert_input_dto)


def main(args):

    init()

    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl.py action -h` to get help with any Splunk Security Content action")
    parser.add_argument("-p", "--path", required=True,
                                        help="path to the Splunk Security Content folder",)
    parser.add_argument("--cached_and_offline", action=argparse.BooleanOptionalAction,
        help="Force cached/offline resources.  While this makes execution much faster, it may result in enrichment which is out of date. This is suitable for use only in development or disconnected environments.")
    parser.add_argument("--skip_enrichment", action=argparse.BooleanOptionalAction,
        help="Skip enrichment of CVEs.  This can significantly decrease the amount of time needed to run content_ctl.")

    parser.set_defaults(cached_and_offline=False, func=lambda _: parser.print_help())

    actions_parser = parser.add_subparsers(title="Splunk Security Content actions", dest="action")
    #new_parser = actions_parser.add_parser("new", help="Create new content (detection, story, baseline)")
    #init_parser = actions_parser.add_parser("init", help="Initialize a repo with scaffolding in place to build a custom app."
    #                                                    "This allows a user to easily add their own content and, eventually, "
    #                                                    "build a custom application consisting of their custom content.")
    new_content_parser = actions_parser.add_parser("new_content", help="Create new security content object")
    #content_changer_parser = actions_parser.add_parser("content_changer", help="Change Security Content based on defined rules")
    validate_parser = actions_parser.add_parser("validate", help="Validates written content")
    generate_parser = actions_parser.add_parser("generate", help="Generates a deployment package for different platforms (splunk_app)")
    #docgen_parser = actions_parser.add_parser("docgen", help="Generates documentation")
    
    reporting_parser = actions_parser.add_parser("reporting", help="Create security content reporting")


    build_parser = actions_parser.add_parser("build", help="Build an application suitable for deployment to a search head")
    #inspect_parser = actions_parser.add_parser("inspect", help="Run appinspect to ensure that an app meets minimum requirements for deployment.")
    #cloud_deploy_parser = actions_parser.add_parser("cloud_deploy", help="Install an application on a target Splunk Cloud Instance.")
    convert_parser = actions_parser.add_parser("convert", help="Convert a sigma detection to a Splunk ESCU detection.")


    # # new arguments
    # new_parser.add_argument("-t", "--type", required=False, type=str, default="detection",
    #                              help="Type of new content to create, please choose between `detection`, `baseline` or `story`. Defaults to `detection`")
    # new_parser.add_argument("-x", "--example_only", required=False, action='store_true',
    #                              help="Generates an example content UPDATE on the fields that need updating. Use `git status` to see what specific files are added. Skips new content wizard prompts.")
    # new_parser.set_defaults(func=new)

    validate_parser.add_argument("-pr", "--product", required=True, type=str, default='all',
        help="Type of package to create, choose between all, `ESCU` or `SSA`.")
    validate_parser.add_argument('--check_references', action=argparse.BooleanOptionalAction, help="The number of threads to use to resolve references.  "
                                   "Larger numbers will result in faster resolution, but will be more likely to hit rate limits or use a large amount of "
                                   "bandwidth.  A larger number of threads is particularly useful on high-bandwidth connections, but does not improve "
                                   "performance on slow connections.")

    validate_parser.set_defaults(func=validate, check_references=False, epilog="""
                Validates security manifest for correctness, adhering to spec and other common items.""")

    generate_parser.add_argument("-o", "--output", required=True, type=str,
        help="Path where to store the deployment package")
    generate_parser.add_argument("-pr", "--product", required=True, type=str,
        help="Type of package to create, choose between `ESCU`, `SSA` or `API`.")
    generate_parser.set_defaults(func=generate)

    # content_changer_choices = ContentChanger.enumerate_content_changer_functions()
    # content_changer_parser.add_argument("-cf", "--change_function", required=True, metavar='{ ' + ', '.join(content_changer_choices) +' }' , type=str, choices=content_changer_choices,
    #                                     help= "Choose from the functions above defined in \nbin/contentctl_core/contentctl/application/use_cases/content_changer.py")

    # content_changer_parser.set_defaults(func=content_changer)

    # docgen_parser.add_argument("-o", "--output", required=True, type=str,
    #     help="Path where to store the documentation")
    # docgen_parser.set_defaults(func=doc_gen)

    new_content_parser.add_argument("-t", "--type", required=True, type=str,
        help="Type of security content object, choose between `detection`, `story`")
    new_content_parser.set_defaults(func=new_content)

    reporting_parser.set_defaults(func=reporting)

    convert_parser.add_argument("-dm", "--data_model", required=False, type=str, default="cim", help="converter target, choose between cim, raw, ocsf")
    convert_parser.add_argument("-lo", "--log_source", required=False, type=str, help="converter log source")
    convert_parser.add_argument("-dp", "--detection_path", required=False, type=str, help="path to a single detection")
    convert_parser.add_argument("-df", "--detection_folder", required=False, type=str, help="path to a detection folder")
    convert_parser.add_argument("-o", "--output", required=True, type=str, help="output path to store the detections")
    convert_parser.set_defaults(func=convert)


    # init_parser.add_argument("-t", "--title", type=str, required=True, help="The title of the application to be built.")
    # init_parser.add_argument("-n", "--name", type=str, required=True, help="The name of the application to be built.")
    # init_parser.add_argument("-v", "--version", type=str, required=True, help="The version of the application to be built.  It should be in MAJOR.MINOR.PATCH format.")
    # init_parser.add_argument("-a", "--author_name", type=str, required=True, help="The name of the application author.")
    # init_parser.add_argument("-e", "--author_email", type=str, required=True, help="The email of the application author.")
    # init_parser.add_argument("-c", "--author_company", type=str, required=True, help="The company of the application author.")
    # init_parser.add_argument("-d", "--description", type=str, required=True, help="A brief description of the app.")
    # init_parser.set_defaults(func=initialize)

    build_parser.add_argument("-o", "--output_dir", required=False, default="build", type=str, help="Directory to output the built package to (default is 'build')")
    build_parser.add_argument("-pr", "--product", required=True, type=str, help="Name of the product to build. This is the name you created during init.  To find the name of your app, look for the name of the folder created in the ./dist folder.")
    build_parser.set_defaults(func=build)


    # inspect_parser.add_argument("-p", "--package_path", required=True, type=str, help="Path to the package to be inspected")
    # inspect_parser.set_defaults(func=inspect)


    # cloud_deploy_parser.add_argument("--app-package", required=True, type=str, help="Path to the package you wish to deploy")
    # cloud_deploy_parser.add_argument("--acs-legal-ack", required=True, type=str, help="specify '--acs-legal-ack=Y' to acknowledge your acceptance of any risks (required)")
    # cloud_deploy_parser.add_argument("--username", required=True, type=str, help="splunk.com username")
    # cloud_deploy_parser.add_argument("--password", required=True, type=str, help="splunk.com password")
    # cloud_deploy_parser.add_argument("--server", required=False, default="https://admin.splunk.com", type=str, help="Override server URL (default 'https://admin.splunk.com')")
    # cloud_deploy_parser.set_defaults(func=cloud_deploy)

    # # parse them
    args = parser.parse_args()
#    try:
    return args.func(args)
#    except Exception as e:
#        print(f"Error for function [{args.func.__name__}]: {str(e)}")
#        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv[1:])
