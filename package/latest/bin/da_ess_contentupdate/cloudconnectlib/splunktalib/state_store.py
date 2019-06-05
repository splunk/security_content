import json
import os
import os.path as op
import time

from ..splunktacollectorlib.common import log as stulog
from ..splunktalib import kv_client as kvc
from ..splunktalib.common import util


def get_state_store(meta_configs,
                    appname,
                    collection_name="talib_states",
                    use_kv_store=False,
                    use_cache_file=True,
                    max_cache_seconds=5):
    # FIXME refactor this
    if util.is_true(use_kv_store):
        return StateStore(meta_configs, appname, collection_name)
    if util.is_true(use_cache_file):
        return CachedFileStateStore(meta_configs, appname, max_cache_seconds)
    return FileStateStore(meta_configs, appname)


class BaseStateStore(object):
    def __init__(self, meta_configs, appname):
        self._meta_configs = meta_configs
        self._appname = appname

    def update_state(self, key, states):
        pass

    def get_state(self, key):
        pass

    def delete_state(self, key):
        pass

    def close(self, key=None):
        pass


class StateStore(BaseStateStore):

    def __init__(self, meta_configs, appname, collection_name="talib_states"):
        """
        :meta_configs: dict like and contains checkpoint_dir, session_key,
         server_uri etc
        :app_name: the name of the app
        :collection_name: the collection name to be used.
        Don"t use other method to visit the collection if you are using
         StateStore to visit it.
        """
        super(StateStore, self).__init__(meta_configs, appname)

        # State cache is a dict from _key to value
        self._states_cache = {}
        self._kv_client = None
        self._collection = collection_name
        self._kv_client = kvc.KVClient(meta_configs["server_uri"],
                                       meta_configs["session_key"])
        kvc.create_collection(self._kv_client, self._collection, self._appname)
        self._load_states_cache()

    def update_state(self, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """

        if key not in self._states_cache:
            self._kv_client.insert_collection_data(
                self._collection, {"_key": key, "value": json.dumps(states)},
                self._appname)
        else:
            self._kv_client.update_collection_data(
                self._collection, key, {"value": json.dumps(states)},
                self._appname)
        self._states_cache[key] = states

    def get_state(self, key=None):
        if key:
            return self._states_cache.get(key, None)
        return self._states_cache

    def delete_state(self, key=None):
        if key:
            self._delete_state(key)
        else:
            [self._delete_state(_key) for _key in self._states_cache.keys()]

    def _delete_state(self, key):
        if key not in self._states_cache:
            return

        self._kv_client.delete_collection_data(
            self._collection, key, self._appname)
        del self._states_cache[key]

    def _load_states_cache(self):
        states = self._kv_client.get_collection_data(
            self._collection, None, self._appname)
        if not states:
            return

        for state in states:
            if "value" in state:
                value = state["value"]
            else:
                value = state

            try:
                value = json.loads(value)
            except Exception:
                pass

            self._states_cache[state["_key"]] = value


def _create_checkpoint_dir_if_needed(checkpoint_dir):
    if os.path.isdir(checkpoint_dir):
        return

    stulog.logger.info(
        "Checkpoint dir '%s' doesn't exist, try to create it",
        checkpoint_dir)
    try:
        os.mkdir(checkpoint_dir)
    except OSError:
        stulog.logger.exception(
            "Failure creating checkpoint dir '%s'", checkpoint_dir
        )
        raise Exception(
            "Unable to create checkpoint dir '{}'".format(checkpoint_dir)
        )


class FileStateStore(BaseStateStore):
    def __init__(self, meta_configs, appname):
        """
        :meta_configs: dict like and contains checkpoint_dir, session_key,
        server_uri etc
        """

        super(FileStateStore, self).__init__(meta_configs, appname)

    def update_state(self, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """

        checkpoint_dir = self._meta_configs["checkpoint_dir"]
        _create_checkpoint_dir_if_needed(checkpoint_dir)

        fname = op.join(checkpoint_dir, key)
        with open(fname + ".new", "w") as jsonfile:
            json.dump(states, jsonfile)

        if op.exists(fname):
            os.remove(fname)

        os.rename(fname + ".new", fname)
        # commented this to disable state cache for local file
        # if key not in self._states_cache:
        # self._states_cache[key] = {}
        # self._states_cache[key] = states

    def get_state(self, key):
        fname = op.join(self._meta_configs["checkpoint_dir"], key)
        if op.exists(fname):
            with open(fname) as jsonfile:
                state = json.load(jsonfile)
                # commented this to disable state cache for local file
                # self._states_cache[key] = state
                return state
        else:
            return None

    def delete_state(self, key):
        fname = op.join(self._meta_configs["checkpoint_dir"], key)
        if op.exists(fname):
            os.remove(fname)


class CachedFileStateStore(BaseStateStore):
    def __init__(self, meta_configs, appname, max_cache_seconds=5):
        """
        :meta_configs: dict like and contains checkpoint_dir, session_key,
        server_uri etc
        """

        super(CachedFileStateStore, self).__init__(meta_configs, appname)
        self._states_cache = {} # item: time, dict
        self._states_cache_lmd = {} #item: time, dict
        self.max_cache_seconds = max_cache_seconds

    def update_state(self, key, states):

        now = time.time()
        if key in self._states_cache:
            last = self._states_cache_lmd[key][0]
            if now - last >= self.max_cache_seconds:
                self.update_state_flush(now, key, states)
        else:
            self.update_state_flush(now, key, states)
        self._states_cache[key] = (now, states)

    def update_state_flush(self, now, key, states):
        """
        :state: Any JSON serializable
        :return: None if successful, otherwise throws exception
        """
        self._states_cache_lmd[key] = (now, states)
        checkpoint_dir = self._meta_configs["checkpoint_dir"]

        _create_checkpoint_dir_if_needed(checkpoint_dir)

        fname = op.join(checkpoint_dir, key)

        with open(fname + ".new", "w") as jsonfile:
            json.dump(states, jsonfile)

        if op.exists(fname):
            os.remove(fname)

        os.rename(fname + ".new", fname)

    def get_state(self, key):
        if key in self._states_cache:
            return self._states_cache[key][1]

        fname = op.join(self._meta_configs["checkpoint_dir"], key)
        if op.exists(fname):
            with open(fname) as jsonfile:
                state = json.load(jsonfile)
                now = time.time()
                self._states_cache[key] = now, state
                self._states_cache_lmd[key] = now, state
                return state
        else:
            return None

    def delete_state(self, key):
        fname = op.join(self._meta_configs["checkpoint_dir"], key)
        if op.exists(fname):
            os.remove(fname)

        if self._states_cache.get(key):
            del self._states_cache[key]
        if self._states_cache_lmd.get(key):
            del self._states_cache_lmd[key]

    def close(self, key=None):
        if not key:
            for k, (t, s) in self._states_cache.iteritems():
                self.update_state_flush(t, k, s)
            self._states_cache.clear()
            self._states_cache_lmd.clear()
        elif key in self._states_cache:
            self.update_state_flush(self._states_cache[key][0], key,
                                    self._states_cache[key][1])
            del self._states_cache[key]
            del self._states_cache_lmd[key]
