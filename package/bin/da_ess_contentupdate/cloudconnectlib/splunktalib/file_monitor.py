import os.path as op
import traceback

from .common import log


class FileMonitor(object):

    def __init__(self, callback, files):
        """
        :files: files to be monidtored with full path
        """

        self._callback = callback
        self._files = files

        self.file_mtimes = {
            file_name: None for file_name in self._files
        }
        for k in self.file_mtimes:
            if not op.exists(k):
                continue

            try:
                if not op.exists(k):
                    continue
                self.file_mtimes[k] = op.getmtime(k)
            except OSError:
                log.logger.error("Getmtime for %s, failed: %s",
                                 k, traceback.format_exc())

    def __call__(self):
        return self.check_changes()

    def check_changes(self):
        log.logger.debug("Checking files=%s", self._files)
        file_mtimes = self.file_mtimes
        changed_files = []
        for f, last_mtime in file_mtimes.iteritems():
            try:
                if not op.exists(f):
                    continue

                current_mtime = op.getmtime(f)
                if current_mtime != last_mtime:
                    file_mtimes[f] = current_mtime
                    changed_files.append(f)
                    log.logger.info("Detect %s has changed", f)
            except OSError:
                pass

        if changed_files:
            if self._callback:
                self._callback(changed_files)
            return True
        return False
