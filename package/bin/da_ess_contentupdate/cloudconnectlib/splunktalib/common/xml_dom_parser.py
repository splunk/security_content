import re
from xml.etree import cElementTree as et


def parse_conf_xml_dom(xml_content):
    """
    @xml_content: XML DOM from splunkd
    """

    m = re.search(r'xmlns="([^"]+)"', xml_content)
    ns = m.group(1)
    m = re.search(r'xmlns:s="([^"]+)"', xml_content)
    sub_ns = m.group(1)
    entry_path = "./{%s}entry" % ns
    stanza_path = "./{%s}title" % ns
    key_path = "./{%s}content/{%s}dict/{%s}key" % (ns, sub_ns, sub_ns)
    meta_path = "./{%s}dict/{%s}key" % (sub_ns, sub_ns)
    list_path = "./{%s}list/{%s}item" % (sub_ns, sub_ns)

    xml_conf = et.fromstring(xml_content)
    stanza_objs = []
    for entry in xml_conf.iterfind(entry_path):
        for stanza in entry.iterfind(stanza_path):
            stanza_obj = {"name": stanza.text,"stanza": stanza.text}
            break
        else:
            continue

        for key in entry.iterfind(key_path):
            if key.get("name") == "eai:acl":
                meta = {}
                for k in key.iterfind(meta_path):
                    meta[k.get("name")] = k.text
                stanza_obj[key.get("name")] = meta
            elif key.get("name") != "eai:attributes":
                name = key.get("name")
                if name.startswith("eai:"):
                    name = name[4:]
                list_vals = [k.text for k in key.iterfind(list_path)]
                if list_vals:
                    stanza_obj[name] = list_vals
                else:
                    stanza_obj[name] = key.text
                    if key.text == "None":
                        stanza_obj[name] = None
        stanza_objs.append(stanza_obj)
    return stanza_objs
