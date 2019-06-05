#!/usr/bin/python
from . import ta_checkpoint_manager as cp
from . import ta_data_collector as tdc


def build_event(host=None,
                source=None,
                sourcetype=None,
                time=None,
                index=None,
                raw_data="",
                is_unbroken=False,
                is_done=False):
    if is_unbroken is False and is_done is True:
        raise Exception('is_unbroken=False is_done=True is invalid')
    return tdc.event_tuple._make([host, source, sourcetype, time, index,
                                  raw_data, is_unbroken, is_done])


class TaDataClient(object):
    def __init__(self,
                 meta_config,
                 task_config,
                 checkpoint_mgr=None,
                 event_writer=None):
        self._meta_config = meta_config
        self._task_config = task_config
        self._checkpoint_mgr = checkpoint_mgr
        self._event_writer = event_writer
        self._stop = False

    def is_stopped(self):
        return self._stop

    def stop(self):
        self._stop = True

    def get(self):
        raise StopIteration


def create_data_collector(dataloader,
                          tconfig,
                          meta_configs,
                          task_config,
                          data_client_cls,
                          checkpoint_cls=None):
    checkpoint_manager_cls = checkpoint_cls or cp.TACheckPointMgr
    return tdc.TADataCollector(tconfig, meta_configs, task_config,
                               checkpoint_manager_cls, data_client_cls,
                               dataloader)


def client_adatper(job_func):
    class TaDataClientAdapter(TaDataClient):
        def __init__(self, all_conf_contents, meta_config, task_config,
                     chp_mgr):
            super(TaDataClientAdapter, self).__init__(meta_config, task_config,
                                                      chp_mgr)
            self._execute_times = 0
            self._gen = job_func(self._task_config, chp_mgr)

        def stop(self):
            """
            overwrite to handle stop control command
            """

            # normaly base class just set self._stop as True
            super(TaDataClientAdapter, self).stop()

        def get(self):
            """
            overwrite to get events
            """
            self._execute_times += 1
            if self.is_stopped():
                # send stop signal
                self._gen.send(self.is_stopped())
                raise StopIteration
            if self._execute_times == 1:
                return self._gen.next()
            return self._gen.send(self.is_stopped())

    return TaDataClientAdapter
