# Timesketch Graph Plugins
This is plugins that show graphs in [Timsketch](https://timesketch.org/) with [Hayabusa](https://github.com/Yamato-Security/hayabusa) logs.
# Installation
Firstly, we need to find a folder of Timesketch server (I deployed it by Docker).

    root@ubuntu:/# find / -name "win_logins.py"
    /var/lib/docker/overlay2/927c07c20c81eb62a9aac5d9faaeab56eed943509a1bcf0aa7f573fc5c8a9ae8/diff/usr/local/lib/python3.10/dist-packages/timesketch/lib/graphs/win_logins.py

Then, copy 3 plugin files into the graph folder.

Finally, import below script into __init__.py file in the same folder.

    from timesketch.lib.graphs import win_logins
    from timesketch.lib.graphs import win_services
    from timesketch.lib.graphs import win_processes
