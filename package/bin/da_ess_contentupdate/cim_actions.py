import collections
import csv
import json
import logging
import logging.handlers
import os
import random
import re
import splunk.rest as rest
import time

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util                import mktimegm, normalizeBoolean

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)


class InvalidResultID(Exception):
    pass


class ModularAction(object):
    DEFAULT_MSGFIELDS = ['signature',
                         'action_name',
                         'search_name',
                         'sid',
                         'orig_sid',
                         'rid',
                         'orig_rid',
                         'app',
                         'user',
                         'action_mode',
                         'action_status']
    DEFAULT_MESSAGE   = 'sendmodaction - ' + ' '.join(['{i}="{{d[{i}]}}"'.format(i=i) for i in DEFAULT_MSGFIELDS])
    # The above yields a string.format() compatible format string:
    #
    #   'sendmodaction - signature="{d[signature]}" action_name="{d[action_name]}"
    #   search_name="{d[search_name]}" sid="{d[sid]}" orig_sid="{d[orig_sid]}"
    #   rid="{d[rid]}" orig_rid="{d[orig_rid]}" app="{d[app]}" user="{d[user]}"
    #   action_mode="{d[action_mode]}" action_status="{d[action_status]}"'

    DEFAULT_DROPEXP  = lambda x: ((x.startswith('_') and x not in ['_raw', '_time'])
                                  or x.startswith('date_')
                                  or x in ['punct', 'sid', 'rid', 'orig_sid', 'orig_rid'])

    DEFAULT_MAPEXP   = lambda x: (x.startswith('tag::')
                                  or x in ['_time', '_raw', 'splunk_server', 'index',
                                           'source', 'sourcetype', 'host', 'linecount',
                                           'timestartpos', 'timeendpos', 'eventtype',
                                           'tag', 'search_name', 'event_hash', 'event_id'])

    DEFAULT_HEADER   = '***SPLUNK*** index="%s" host="%s" source="%s"'
    DEFAULT_BREAKER  = '==##~~##~~  1E8N3D4E6V5E7N2T9 ~~##~~##==\n'
    DEFAULT_IDLINE   = '***Common Action Model*** orig_action_name="%s" orig_sid="%s" orig_rid="%s" sourcetype="%s"\n'
    DEFAULT_INDEX    = 'summary'
    DEFAULT_CHUNK    = 50000

    SHORT_FORMAT     = '%(asctime)s %(levelname)s %(message)s'

    def __init__(self, settings, logger, action_name='unknown'):
        """ Initialize ModularAction class.

        @param settings:    A modular action payload in JSON format.
        @param logger:      A logging instance.
                            Recommend using ModularAction.setup_logger.
        @param action_name: The action name.
                            action_name in payload will take precedence.
        """
        self.settings      = json.loads(settings)
        self.logger        = logger
        self.session_key   = self.settings.get('session_key')
        self.sid           = self.settings.get('sid')
        self.sid_snapshot  = ''
        ## if sid contains rt_scheduler with snapshot-sid; drop snapshot-sid
        ## sometimes self.sid may be an integer (1465593470.1228)
        try:
            rtsid    = re.match('^(rt_scheduler.*)\.(\d+)$', self.sid)
            if rtsid:
                self.sid          = rtsid.group(1)
                self.sid_snapshot = rtsid.group(2)
        except:
            pass

        ## rid_ntuple is a named tuple that represents
        ## the three variables that change on a per-result basis
        self.rid_ntuple    = collections.namedtuple('ID', ['orig_sid','rid','orig_rid'])
        ## rids is a list of rid_ntuple values
        ## automatically maintained by update() calls
        self.rids          = []
        ## current orig_sid based on update()
        ## aka self.rids[-1].orig_sid
        self.orig_sid      = ''
        ## current rid based on update()
        ## aka self.rids[-1].rid
        self.rid           = ''
        ## current orig_rid based on update()
        ## aka self.rids[-1].orig_rid
        self.orig_rid      = ''

        self.results_file  = self.settings.get('results_file')
        ## info
        self.info          = {}
        if self.results_file:
            self.info_file = os.path.join(os.path.dirname(self.results_file), 'info.csv')
        self.search_name   = self.settings.get('search_name')
        self.app           = self.settings.get('app')
        self.user          = self.settings.get('user') or self.settings.get('owner')
        self.configuration = self.settings.get('configuration', {})
        ## enforce configuration is a 'dict'
        if not isinstance(self.configuration, dict):
            self.configuration = {}
        ## set loglevel to DEBUG if verbose
        if normalizeBoolean(self.configuration.get('verbose', 'false')):
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug('loglevel set to DEBUG')
        ## use | sendalert param.action_name=$action_name$
        self.action_name = self.configuration.get('action_name') or action_name
        ## use sid to determine action_mode
        if isinstance(self.sid, basestring) and 'scheduler' in self.sid:
            self.action_mode = 'saved'
        else:
            self.action_mode = 'adhoc'

        self.action_status = ''
        ## Since we don't use the result object we get from settings it will be purged
        try:
            del self.settings['result']
        except Exception:
            pass
        ## events
        self.events = []

    def addinfo(self):
        """ The purpose of this method is to populate the
        modular action info variable with the contents of info.csv.

        @raise Exception: raises Exception if self.info_file could not be opened
                          or if there were problems parsing the info.csv data
        """
        if self.info_file:
            try:
                with open(self.info_file, 'rU') as fh:
                    self.info = csv.DictReader(fh).next()
            except Exception as e:
                self.message('Could not retrieve info.csv', level=logging.WARN)

    def addjobinfo(self):
        """ The purpose of this method is to populate the job variable
        with the contents from REST (/services/search/jobs/<sid>)

        SPL-112815 - sendalert - not all $job.<param>$ parameters come through

        @raise Exception: raises Exception if search job information could not
                          be retrieved via REST (search/jobs) based on self.sid
        """
        self.job = {}
        if self.sid:
            try:
                response, content = rest.simpleRequest('search/jobs/%s' % self.sid,
                                        sessionKey=self.session_key,
                                        getargs={'output_mode': 'json'})
                if response.status == 200:
                    self.job = json.loads(content)['entry'][0]['content']
                    self.message('Successfully retrieved search job info')
                    self.logger.debug(self.job)
                else:
                    self.message('Could not retrieve search job info', level=logging.WARN)
            except Exception as e:
                self.message('Could not retrieve search job info', level=logging.WARN)

    def message(self, signature, status=None, rids=None, level=logging.INFO, **kwargs):
        """ The purpose of this method is to provide a common messaging interface.

        @param signature: A string representing the message we want to log.
        @param status:    An optional status that we want to log.
                          Defaults to None.
        @param rids:      An optional list of rid_ntuple values in case we
                          want to generate the message for multiple rids.
                          Defaults to None (use the rid currently loaded).
        @param level:     The logging level to use when writing the message.
                          Defaults to logging.INFO (INFO)
        @param kwargs:    Additional keyword arguments to be included with the
                          message.
                          Defaults to "no arguments".

        @return message:  This method logs the message; however, for
                          backwards compatibility we also return the message.
        """
        ## status
        status = status or self.action_status or ''
        ## rid
        if not isinstance(rids, list):
            rids = [self.rid_ntuple(self.orig_sid, self.rid, self.orig_rid)]
        ## kwargs - prune any duplicate keys based on DEFAULT_MSGFIELDS
        ##          prune any keys with special characters [A-Za-z_]+
        newargs = [x for x in kwargs\
            if (x not in ModularAction.DEFAULT_MSGFIELDS) and re.match('[A-Za-z_]+', x)]
        ## MSG
        msg = '%s %s' % (ModularAction.DEFAULT_MESSAGE, ' '.join(['{i}="{{d[{i}]}}"'.format(i=i) for i in newargs]))

        # This will set the default value of any value NOT in the dictionary to the
        # empty string.
        argsdict = collections.defaultdict(str)
        # order is important here - here we update first from kwargs, then from our
        # expected arg set.
        argsdict.update(kwargs)
        argsdict.update({
            'signature':     signature or '',
            'action_name':   self.action_name or '',
            'search_name':   self.search_name or '',
            'sid':           self.sid or '',
            'app':           self.app or '',
            'user':          self.user or '',
            'action_mode':   self.action_mode or '',
            'action_status': status
        })

        for rid_ntuple in rids:
            if len(rid_ntuple)==3:
                ## Update the arguments dictionary
                argsdict.update({
                    'orig_sid': rid_ntuple.orig_sid or '',
                    'rid':      rid_ntuple.rid or '',
                    'orig_rid': rid_ntuple.orig_rid or ''
                })
                ## This is where the magic happens. The format string will use the
                ## attributes of "argsdict"
                message = msg.format(d=argsdict)
                ## prune empty string key-value pairs
                for match in re.finditer('[A-Za-z_]+=\"\"(\s|$)', message):
                    message = message.replace(match.group(0),'',1)
                message = message.strip()
                self.logger.log(level, message)
            else:
                self.logger.warn('Could not unpack rid_ntuple')
                message = ''

        return message

    def update(self, result):
        """ The purpose of this method is to update the ModularAction instance
        identifiers based on the current result being operated on.

        This is the most important method in the library as it sets up
        rid, orig_sid, and orig_rid to be used by subsequent class methods.

        Not calling update() immediately for each result before doing additional
        work can have adverse affects.

        @param signature: A string representing the message we want to log.
        @param status:    An optional status that we want to log.
                          Defaults to None.
        @param rids:      An optional list of rid_ntuple values in case we
                          want to generate the message for multiple rids.
                          Defaults to None (use the rid currently loaded).
        @param level:     The logging level to use when writing the message.
                          Defaults to logging.INFO (INFO)
        @param kwargs:    Additional keyword arguments to be included with the
                          message.
                          Defaults to "no arguments".

        @return message:  This method logs the message; however, for
                          backwards compatiblity we also return the message.
        """
        ## This is for events/results that were created as the result of a previous action
        self.orig_sid = result.get('orig_sid', '')
        ## This is for events/results that were created as the result of a previous action
        self.orig_rid = result.get('orig_rid', '')
        if 'rid' in result and isinstance(result['rid'], (basestring, int)):
            self.rid = str(result['rid'])
            if self.sid_snapshot:
                self.rid = '%s.%s' % (self.rid, self.sid_snapshot)
            ## add result info to list of named tuples
            self.rids.append(self.rid_ntuple(self.orig_sid, self.rid, self.orig_rid))
        else:
            raise InvalidResultID('Result must have an ID')

    def invoke(self):
        """ The purpose of this method is to generate per-result invocation messages.
        This method is used to identify that an action is being attempted on a per-result basis.

        Remember to call update() prior to invoke() to ensure that the invocation message
        reflects the appropriate identifiers.
        """
        self.message('Invoking modular action')

    def result2stash(self, result, dropexp=DEFAULT_DROPEXP, mapexp=DEFAULT_MAPEXP, addinfo=False):
        """ The purpose of this method is to formulate an event in stash format

        @param result:  The result dictionary to generate a stash event for.
        @param dropexp: A lambda expression used to determine whether a field
                        should be dropped or not.
                        Defaults to DEFAULT_DROPEXP.
        @param mapexp:  A lambda expression used to determine whether a field
                        should be mapped (prepended with "orig_") or not.
                        Defaults to DEFAULT_MAPEXP.
        @param addinfo: Whether or not to add search information to the event.
                        "info" includes search_now, info_min_time, info_max_time,
                        and info_search_time fields.
                        Requires that information was loaded into the ModularAction
                        instance via addinfo()

        @return _raw:   Returns a string which represents the result in stash format.

        The following example has been broken onto multiple lines for readability:
        06/21/2016 10:00:00 -0700,
        search_name="Access - Brute Force Access Behavior Detected - Rule",
        search_now=0.000, info_min_time=1466528400.000, info_max_time=1466532600.000, info_search_time=1465296264.179,
        key1=key1val, key2=key2val, key3=key3val, key4=key4val1, key4=key4val2, ...
        """
        dropexp      = dropexp or (lambda x: False)
        mapexp       = mapexp  or (lambda x: False)
        orig_dropexp = lambda x: x.startswith('orig_') and x[5:] in result and mapexp(x[5:])

        ## addinfo
        if addinfo:
            result['info_min_time']    = self.info.get('_search_et', '0.000')
            info_max_time              = self.info.get('_search_lt')
            if not info_max_time or info_max_time==0 or info_max_time=='0':
                info_max_time = '+Infinity'
            result['info_max_time']    = info_max_time
            result['info_search_time'] = self.info.get('_timestamp', '')

        ## construct _raw
        _raw = '%s' % result.get('_time', mktimegm(time.gmtime()))
        if self.search_name:
            _raw += ', search_name="%s"' % self.search_name

        processed_keys = []
        for key, val in sorted(result.items()):
            vals = []
            ## if we have a proper mv field
            if (key.startswith('__mv_')
                and val and isinstance(val, basestring)
                and val.startswith('$') and val.endswith('$')):
                real_key = key[5:]
                vals     = val[1:-1].split('$;$')
            ## if proper sv field
            elif val and not key.startswith('__mv_'):
                real_key = key
                vals     = [val]

            ## if we have vals and key hasn't been processed
            ## and key is not to be dropped...
            if (vals
                and (real_key not in processed_keys)
                and not dropexp(real_key)
                and not orig_dropexp(real_key)):
                ## iterate vals
                for val in vals:
                    ## format literal '$'
                    if key.startswith('__mv'):
                        val = val.replace('$$', '$')
                    ## escape quotes
                    if isinstance(val, basestring):
                        val = val.replace('"', r'\"')
                    ## check map
                    if mapexp(real_key):
                        _raw += ', %s="%s"' % ('orig_' + real_key.lstrip('_'), val)
                    else:
                        _raw += ', %s="%s"' % (real_key, val)
                processed_keys.append(real_key)

        return _raw

    def addevent(self, raw, sourcetype, cam_header=True):
        """ The purpose of this method is to add a properly constructed event
        to the events list in the ModularAction instance.  This ensures events
        are created with the appropriate index-time header.

        The index-time header is responsible for setting sourcetype,
        orig_action_name, orig_sid, and orig_rid.  The index-time header will
        not be present in the _raw of generated events.

        Remember to call update() prior to addevent() to ensure that the events
        reflect the appropriate orig_sid and orig_rid identifiers.

        @param raw:        The text of the event you want to generate.
        @param sourcetype: The sourcetype of the event you want to generate.
        @param cam_header: Optionally exclude the inclusion of the index-time header.
                           Defaults to True (include header).
        """
        if cam_header:
            if self.orig_sid:
                action_idline = ModularAction.DEFAULT_IDLINE % (
                                    self.action_name,
                                    self.orig_sid,
                                    self.orig_rid,
                                    sourcetype)
            else:
                action_idline = ModularAction.DEFAULT_IDLINE % (
                                    self.action_name,
                                    self.sid,
                                    self.rid,
                                    sourcetype)
            self.events.append(action_idline + raw)
        else:
            self.events.append(raw)

    def writeevents(self, index='summary', host=None, source=None, fext='common_action_model'):
        """ The purpose of this method is to create arbitrary splunk events
        from the list of events in the ModularAction instance.

        Please use addevent() for populating the list of events in
        the ModularAction instance.

        @param index:  The index to write the events to.
                       Defaults to "summary".
        @param host:   The value of host the events should take on.
                       Defaults to None (auto).
        @param source: The value of source the events should take on.
                       Defaults to None (auto).
        @param fext:   The extension of the file to write out.
                       Files are written to $SPLUNK_HOME/var/spool/splunk.
                       File extensions can only contain word characters,
                       dash, and have a 200 char max.
                       "stash_" is automatically prepended to all extensions.
                       Defaults to "common_action_model" ("stash_common_action_model").
                       Only override if you've set up a corresponding props.conf
                       stanza to handle the extension.

        @return bool:  Returns True if all events were successfully written
                       Returns False if any errors were encountered
        """
        ## internal makeevents method for normalizing strings
        ## that will be used in the various headers we write out
        def get_string(input, default):
            try:
                return input.replace('"', '_')
            except AttributeError:
                return default

        if self.events:
            ## sanitize file extension
            if not fext or not re.match('^[\w-]+$', fext):
                self.logger.warn('Requested file extension was ignored due to invalid characters')
                fext = 'common_action_model'
            elif len(fext)>200:
                self.logger.warn('Requested file extension was ignored due to length')
                fext = 'common_action_model'
            ## header
            header_line = ModularAction.DEFAULT_HEADER % (
                            get_string(index, ModularAction.DEFAULT_INDEX),
                            get_string(host, ''),
                            get_string(source, ''))
            ## process event chunks
            for chunk in (self.events[x:x+ModularAction.DEFAULT_CHUNK]
                          for x in xrange(0, len(self.events), ModularAction.DEFAULT_CHUNK)):
                ## initialize output string
                default_breaker = '\n' + ModularAction.DEFAULT_BREAKER
                fout            = header_line + default_breaker + (default_breaker).join(chunk)
                ## write output string
                try:
                    fn = '%s_%s.stash_%s' % (mktimegm(time.gmtime()), random.randint(0, 100000), fext)
                    fp = make_splunkhome_path(['var', 'spool', 'splunk', fn])
                    ## obtain fh
                    with open(fp, 'w') as fh:
                        fh.write(fout)
                except:
                    signature = 'Error obtaining file handle during makeevents'
                    self.message(signature, level=logging.ERROR, file_path=fp)
                    self.logger.exception(signature + ' file_path=%s' % fp)
                    return False
            self.message('Successfully created splunk events', event_count=len(self.events))
            return True
        return False

    def dowork(self):
        """ This method serves as an illustration stub.
        Serves as a container for operations which satisfy the nature of the action.
        For instance, the third party API call.

        For cleanliness it is recommended that you subclass ModularAction
        and implement your own dowork() method.
        """
        return

    @staticmethod
    def setup_logger(name, level=logging.INFO, maxBytes=25000000, backupCount=5, format=SHORT_FORMAT):
        """ Set up a logging instance.

        @param name:        The log file name.
                            We recommend "$action_name$_modalert".
        @param level:       The logging level.
        @param maxBytes:    The maximum log file size before rollover.
        @param backupCount: The number of log files to retain.

        @return logger:     Returns an instance of logger
        """
        logfile = make_splunkhome_path(['var', 'log', 'splunk', name + '.log'])
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file

        # Prevent re-adding handlers to the logger object, which can cause duplicate log lines.
        handler_exists = any([True for h in logger.handlers if h.baseFilename == logfile])
        if not handler_exists:
            file_handler = logging.handlers.RotatingFileHandler(logfile, maxBytes=maxBytes, backupCount=backupCount)
            formatter = logging.Formatter(format)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger
