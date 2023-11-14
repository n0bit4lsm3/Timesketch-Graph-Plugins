"""
Graph plugin for Windows services.
Author: n0bit4lsm3
"""

from timesketch.lib.graphs.interface import BaseGraphPlugin
from timesketch.lib.graphs import manager


class WinServiceGraph(BaseGraphPlugin):
    """Graph plugin for Windows services."""

    NAME = "WinService"
    DISPLAY_NAME = "Windows services"

    def generate(self):
        """Generate the graph.

        Returns:
            Graph object instance.
        """
        query = "EventID:7045"
        return_fields = ["Computer", "Details", "ExtraFieldInfo"]

        events = self.event_stream(query_string=query, return_fields=return_fields)

        for event in events:
            computer_name = event["_source"].get("Computer", "UNKNOWN")

            # Skip event if we don't have enough data to build the graph.
            try:
                details = event["_source"].get("Details").split(" ¦ ")
                extrainfo = event["_source"].get("ExtraFieldInfo").split(" ¦ ")

                service_name = details[0].replace("Svc: ", "")
                image_path = details[1].replace("Path: ", "")
                service_type = extrainfo[0].replace("ServiceType: ", "")
                start_type = details[3].replace("StartType: ", "")
            except IndexError:
                continue

            computer = self.graph.add_node(computer_name, {"type": "computer"})
            service = self.graph.add_node(
                service_name, {"type": "winservice", "image_path": image_path}
            )

            self.graph.add_edge("Unknown", service, start_type, event)
            self.graph.add_edge(service, computer, service_type, event)

        self.graph.commit()

        return self.graph


manager.GraphManager.register_graph(WinServiceGraph)
