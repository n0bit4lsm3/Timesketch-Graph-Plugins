"""
Graph plugin for Windows processes in Event Logs.
Author: n0bit4lsm3
"""

from timesketch.lib.graphs.interface import BaseGraphPlugin
from timesketch.lib.graphs import manager


class WinProcessesGraph(BaseGraphPlugin):
    """Graph plugin for Windows processes."""

    NAME = "WinProcesses"
    DISPLAY_NAME = "Windows processes"

    def generate(self):
        """Generate the graph.

        Returns:
            Graph object instance.
        """
        query = "EventID:4688"
        return_fields = ["Computer", "Details", "ExtraFieldInfo"]

        events = self.event_stream(query_string=query, return_fields=return_fields)
        
        for event in events:
            # get computer name
            computer_name = event["_source"].get("Computer")

            # Skip event if we don't have enough data to build the graph.
            try:
                # get process name and process id
                details = event["_source"].get("Details").split(" ¦ ")
                process_path = details[1].replace("Proc: ", "")
                process_name = ""
                try:
                    process_name = process_path.split("\\")[-1]
                except:
                    process_name = process_path.split("/")[-1]


                # get parent process name and parent process id
                extrafieldinfo = event["_source"].get("ExtraFieldInfo").split(" ¦ ")
                parent_process_path = extrafieldinfo[1].replace("ParentProcessName: ", "")
                parent_process_name = ""
                try:
                    parent_process_name = parent_process_path.split("\\")[-1]
                except:
                    parent_process_name = parent_process_path.split("/")[-1]

            except IndexError:
                continue

            # handle if don't have parent process name
            if "ProcessId" in parent_process_path:
                # add nodes
                computer = self.graph.add_node(computer_name, {"type": "computer"})
                processname = self.graph.add_node(process_name, {"type": "processname", "image_path" : process_path})
                # add edge
                self.graph.add_edge(computer, processname, "", event)
            else:
                # add nodes
                computer = self.graph.add_node(computer_name, {"type": "computer"})
                parentprocessname = self.graph.add_node(parent_process_name, {"type": "parentprocessname", "parent_iamge_path" : parent_process_path})
                processname = self.graph.add_node(process_name, {"type": "processname", "image_path" : process_path})
                # add edge
                self.graph.add_edge(computer, parentprocessname, "", event)
                self.graph.add_edge(parentprocessname, processname, "", event)

        self.graph.commit()

        return self.graph


manager.GraphManager.register_graph(WinProcessesGraph)
