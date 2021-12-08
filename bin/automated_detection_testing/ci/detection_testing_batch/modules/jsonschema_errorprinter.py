"""
Courtesy https://github.com/ccpgames/jsonschema-errorprinter with minor
updates to support Python 3 (changed cStringIO to io), to print out
multiple errors, the ability to place default values, and a few
other small changes.

Licensed under the MIT License, reproduced below:
Copyright © 2015 CCP hf.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
THERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
"""

"""
    Json Schema Validation Error Pretty-printer.
    ---------------------------------------------------

    Makes a user friendly error message from a ValidationError.

"""



import io
import json
import jsonschema
import jsonschema.validators

# The 'default' field is really just for documentation in the
# json schema.  We would like to use it to actually fill in
# values when they aren't supplied.  This code is provided
# by the jsonschema project itself because this behavior
# is not part of the default jsonschema definition
# https://python-jsonschema.readthedocs.io/en/latest/faq/
def extend_with_default(validator_class):
    validate_properties = validator_class.VALIDATORS["properties"]

    def set_defaults(validator, properties, instance, schema):
        for property, subschema in properties.items():
            if "default" in subschema:
                instance.setdefault(property, subschema["default"])

        for error in validate_properties(
            validator, properties, instance, schema,
        ):
            yield error

    return jsonschema.validators.extend(
        validator_class, {"properties": set_defaults},
    )


def check_json(json_object, schema, context=None) -> tuple[list[str], dict]:
    try:
        DefaultValidatingDraft7Validator = extend_with_default(
                jsonschema.Draft7Validator)
        
        
        validator = DefaultValidatingDraft7Validator(schema, jsonschema.FormatChecker())
        #validator = jsonschema.Draft7Validator(schema, jsonschema.FormatChecker())
        errors_formatted = []
        
        for error in sorted(validator.iter_errors(json_object), key=str):

            #validate(json_object, schema, format_checker=FormatChecker())
            # except jsonschema.ValidationError as e:
            report = generate_validation_error_report(error, json_object)
            
            #note = "\n*** Note - If there is more than one error, only the first error is shown ***\n\n"
            if context:
                errors_formatted.append(
                    "Schema check failed for '{}'\n{}".format(context, report))
                # return note + "Schema check failed for '{}'\n{}".format(context, report)
            else:
                errors_formatted.append(
                    "Schema check failed.\n{}".format(report))
                # return note + "Schema check failed.\n{}".format(report)
        if len(errors_formatted) == 0:
            #DefaultValidatingDraft7Validator = extend_with_default(
            #    jsonschema.Draft7Validator)
            #DefaultValidatingDraft7Validator(schema).validate(json_object)
            return (errors_formatted, json_object)
        else:
            return (errors_formatted, {})
    except Exception as e:
        # Some error occurred, probably related to the schema itself
        raise(Exception("Error validating the JSON Schema: %s" % (str(e))))


def generate_validation_error_report(
    e,
    json_object,
    lines_before=7,
    lines_after=7
):
    """
    Generate a detailed report of a schema validation error.

    'e' is a jsonschema.ValidationError exception that errored on
    'json_object'.

    Steps to discover the location of the validation error:
    1. Traverse the json object using the 'path' in the validation exception
       and replace the offending value with a special marker.
    2. Pretty-print the json object indendented json text.
    3. Search for the special marker in the json text to find the actual
       line number of the error.
    4. Make a report by showing the error line with a context of
      'lines_before' and 'lines_after' number of lines on each side.
    """

    if json_object is None:
        return "'json_object' cannot be None."
    if not e.path:
        return str(e)
    marker = "3fb539deef7c4e2991f265c0a982f5ea"

    # Find the object that is erroring, and replace it with the marker.
    ob_tmp = json_object
    for entry in list(e.path)[:-1]:
        ob_tmp = ob_tmp[entry]

    orig, ob_tmp[e.path[-1]] = ob_tmp[e.path[-1]], marker

    # Pretty print the object and search for the marker.
    json_error = json.dumps(json_object, indent=4)
    string_io_instance = io.StringIO(json_error)
    errline = None

    for lineno, text in enumerate(string_io_instance):
        if marker in text:
            errline = lineno
            break

    if errline is not None:
        # Re-create report.
        report = []
        ob_tmp[e.path[-1]] = orig
        json_error = json.dumps(json_object, indent=4)
        string_io_instance = io.StringIO(json_error)

        for lineno, text in enumerate(string_io_instance):
            if lineno == errline:
                line_text = "{:4}: >>>".format(lineno+1)
            else:
                line_text = "{:4}:    ".format(lineno+1)
            report.append(line_text + text.rstrip("\n"))

        report = report[max(0, errline-lines_before):errline+1+lines_after]

        s = "Error in line {}:\n".format(errline+1)
        s += "\n".join(report)
        s += '\n\tREASON:' + str(e).split('\n')[0]
        #s += "\n\n" + str(e).replace("u'", "'")
    else:
        s = str(e)
    return s
