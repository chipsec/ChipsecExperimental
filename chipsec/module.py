# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com


import importlib
import re
import traceback
from chipsec.logger import logger
from chipsec.module_common import ModuleResult
from chipsec.module_common import BaseModule

MODPATH_RE = re.compile(r"^\w+(\.\w+)*$")


class Module():
    def __init__(self, name):
        self.logger = logger()
        self.name = name
        self.module = None
        self.mod_obj = None

    def __lt__(self, other):
        return self.name < other.name

    def __le__(self, other):
        return self.name <= other.name

    def __gt__(self, other):
        return self.name > other.name

    def __ge__(self, other):
        return self.name >= other.name

    def get_name(self):
        return self.name

    def do_import(self):
        loaded = False
        if not MODPATH_RE.match(self.get_name()):
            self.logger.error("Invalid module path: {}".format(self.name))
        else:
            try:
                self.module = importlib.import_module(self.name)
                loaded = True
                self.logger.log_debug("imported: {}".format(self.name))
            except BaseException as msg:
                self.logger.error("Exception occurred during import of {}: '{}'".format(self.name, str(msg)))
                self.logger.log_debug(traceback.format_exc())
                raise msg
        return loaded

    def run(self, module_argv):
        result = self.get_module_object()

        if self.mod_obj is not None and result == ModuleResult.PASSED:
            if module_argv is not None:
                self.logger.log("[*] Module arguments ({:d}):".format(len(module_argv)))
                self.logger.log(module_argv)
            else:
                module_argv = []

            if isinstance(self.mod_obj, BaseModule):
                if self.mod_obj.is_supported():
                    result = self.mod_obj.run(module_argv)
                else:
                    if self.mod_obj.res == ModuleResult.NOTAPPLICABLE:
                        result = ModuleResult.NOTAPPLICABLE
                        self.logger.log("Skipping module {} since it is not supported in this platform".format(self.name))
                    else:
                        result = ModuleResult.SKIPPED
                        self.logger.log("Skipping module {} since it is not supported in this platform".format(self.name))

        return result

    def get_module_object(self):
        result = ModuleResult.PASSED
        if self.mod_obj is None:
            try:
                pkg = getattr(self.module, "__package__")
                class_name = getattr(self.module, "__name__")
                if pkg:
                    class_name = class_name.replace(pkg, '')
                if class_name.startswith('.'):
                    class_name = class_name.replace('.', '')
                for iname, iref in self.module.__dict__.items():
                    if isinstance(iref, type):
                        if issubclass(iref, BaseModule):
                            if iname.lower() == class_name.lower():
                                self.mod_obj = iref()
                if self.mod_obj is None:
                    result = ModuleResult.ERROR
            except (AttributeError, TypeError):
                result = ModuleResult.ERROR
        return result

    def get_location(self):
        myfile = ''
        try:
            myfile = getattr(self.module, "__file__")
        except AttributeError:
            pass
        return myfile

    def get_tags(self):
        module_tags = []
        metadata_tags = []
        try:
            module_tags = getattr(self.module, 'TAGS')
            metadata_tags = getattr(self.module, 'MD_TAGS')
        except AttributeError:
            pass

        return module_tags, metadata_tags

    def __str__(self):
        return self.get_name()
