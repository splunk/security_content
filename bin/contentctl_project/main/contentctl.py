import sys
import argparse
import os

from contentctl_core.application.use_cases.content_changer import ContentChanger, ContentChangerInputDto
from contentctl_core.application.use_cases.content_organizer import ContentOrganizer, ContentOrganizerInputDto
from contentctl_core.application.factory.object_factory import ObjectFactoryInputDto
from contentctl_infrastructure.builder.security_content_object_builder import SecurityContentObjectBuilder
from contentctl_infrastructure.builder.security_content_director import SecurityContentDirector
from contentctl_infrastructure.adapter.obj_to_yml_adapter import ObjToYmlAdapter


def init(args):

    print("""
Running Splunk Security Content Control Tool (contentctl) v{0}
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

    # parse config
    security_content_path = os.path(args.path).resolve()
    if security_content_path.is_dir():
        print("contentctl is reading from path {0}".format(
            security_content_path))
    else:
        print("ERROR: contentctl failed to find security_content project")
        sys.exit(1)
    return str(security_content_path)


def content_changer(args) -> None:
    factory_input_dto = ObjectFactoryInputDto(
        os.path.abspath(args.path),
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    input_dto = ContentChangerInputDto(
        ObjToYmlAdapter(),
        factory_input_dto,
        args.change_function
    )

    content_changer = ContentChanger()
    content_changer.execute(input_dto)


def content_organizer(args) -> None:
    factory_input_dto = ObjectFactoryInputDto(
        os.path.abspath(args.path),
        SecurityContentObjectBuilder(),
        SecurityContentDirector()
    )

    input_dto = ContentOrganizerInputDto(
        ObjToYmlAdapter(),
        factory_input_dto,
        os.path.abspath(args.security_content_path)
    )

    content_organizer = ContentOrganizer()
    content_organizer.execute(input_dto)


def main(args):
    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `contentctl.py action -h` to get help with any Splunk Security Content action")
    parser.set_defaults(func=lambda _: parser.print_help())

    actions_parser = parser.add_subparsers(title="Splunk Security Content actions", dest="action")
    #new_parser = actions_parser.add_parser("new", help="Create new content (detection, story, baseline)")
    #validate_parser = actions_parser.add_parser("validate", help="Validates written content")
    #generate_parser = actions_parser.add_parser("generate", help="Generates a deployment package for different platforms (splunk_app)")
    content_changer_parser = actions_parser.add_parser("content_changer", help="Change Security Content based on defined rules")
    content_organizer_parser = actions_parser.add_parser("content_organizer", help="Organize Security Content")

    # # new arguments
    # new_parser.add_argument("-t", "--type", required=False, type=str, default="detection",
    #                              help="Type of new content to create, please choose between `detection`, `baseline` or `story`. Defaults to `detection`")
    # new_parser.add_argument("-x", "--example_only", required=False, action='store_true',
    #                              help="Generates an example content UPDATE on the fields that need updating. Use `git status` to see what specific files are added. Skips new content wizard prompts.")
    # new_parser.set_defaults(func=new)

    # # validate arguments
    # validate_parser.set_defaults(func=validate, epilog="""
    #     Validates security manifest for correctness, adhering to spec and other common items.""")

    # # generate arguments
    # generate_parser.add_argument("-o", "--output", required=False, type=str, default="dist/escu",
    #                                  help="Path where to store the deployment package, defaults to `dist/escu`")
    # generate_parser.add_argument("-p", "--product", required=False, type=str, default="ESCU",
    #                              help="Type of package to create, choose between `ESCU`, `DevSecOps`, `SAAWS`, or `SSA`. Defaults to `ESCU`")
    # generate_parser.set_defaults(func=generate)
    
    content_changer_parser.add_argument("-p", "--path", required=True, 
                                        help="path to the Splunk Security Content folder")
    content_changer_parser.add_argument("-cf", "--change_function", required=True, type=str,
                                      help="Define a change funtion defined in bin/contentctl_core/contentctl/application/use_cases/content_changer.py")
    content_changer_parser.set_defaults(func=content_changer)

    content_organizer_parser.add_argument("-p", "--path", required=True, 
                                        help="path to the Splunk Security Content folder")
    content_organizer_parser.add_argument("-scp", "--security_content_path", required=True, 
                                        help="path to the Splunk Security Content")
    content_organizer_parser.set_defaults(func=content_organizer)


    # # parse them
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])