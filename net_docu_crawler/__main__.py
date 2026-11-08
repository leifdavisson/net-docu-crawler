# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys

from net_docu_crawler.dependency_checker import ensure_dependencies

if __name__ == "__main__":
    auto_install = "--install-deps" in sys.argv
    if "--install-deps" in sys.argv:
        sys.argv.remove("--install-deps")

    if not ensure_dependencies(auto_install=auto_install, prompt=True):
        sys.exit(1)

    from net_docu_crawler.crawler import main

    main()
