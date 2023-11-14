"""
Graph plugin for Windows logins.
Author: n0bit4lsm3
"""

from timesketch.lib.graphs.interface import BaseGraphPlugin
from timesketch.lib.graphs import manager


class WinLoginsGraph(BaseGraphPlugin):
    """Graph plugin for Windows logins."""

    NAME = "WinLogins"
    DISPLAY_NAME = "Windows logins"

    def generate(self):
        """Generate the graph.

        Returns:
            Graph object instance.
        """
        query = "EventID:4624 OR EventID:4625"
        return_fields = ["Computer", "EventID", "Details", "ExtraFieldInfo"]

        events = self.event_stream(query_string=query, return_fields=return_fields)

        for event in events:

            computer_name = event["_source"].get("Computer")

            # get user name and logon type
            details_str = event["_source"].get("Details")
            details_arr = details_str.split(" ¦ ")
            
            # get user name
            username = details_arr[1].replace("TgtUser: ", "")

            # get event id
            event_id = str(event["_source"].get("EventID"))

            # get logon type
            try:
                logon_type = details_arr[0].replace("Type: ", "")
            except:
                logon_type = "Unkown"

            computer = self.graph.add_node(computer_name, {"type": "computer"})
            eventid = self.graph.add_node(event_id, {"type": "eventid"})
            user = self.graph.add_node(username, {"type": "user"})
            self.graph.add_edge(user, eventid, logon_type, event)
            self.graph.add_edge(eventid, computer, "", event)

        self.graph.commit()

        return self.graph


manager.GraphManager.register_graph(WinLoginsGraph)
