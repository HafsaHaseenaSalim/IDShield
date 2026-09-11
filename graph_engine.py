"""
IDShield — cross-record link analysis.

Most fraud checks ask "does this attempt look suspicious on its own?". That
question is easy to defeat: a synthetic identity is built specifically so that
every field is individually plausible. Nothing about "Sara Haddad, born 1994,
lives at 12 Falcon Street" is odd until you notice that four other applicants
this week gave the same address and the same device.

So this module asks the other question: what is this identity connected to?

The graph is bipartite - identity nodes on one side, shared-attribute nodes
(device, IP, phone, address, document hash) on the other. Two identities are
connected when they share an attribute. A connected component is therefore a
cluster of identities bound together by shared infrastructure, which is what a
fraud ring physically looks like: one operator, one laptop, one phone, many
"people".

Cost note: rebuilding the graph for every attempt would be quadratic, so the
class maintains state incrementally and the replay stays linear.
"""

import networkx as nx
import hashlib
import security

import config

LINK_ATTRIBUTES = ("device_id", "ip_address", "phone", "address", "document_hash")

# Not every shared attribute means the same thing, and treating them alike is
# how a fraud engine ends up locking families out of government services.
#
# WEAK: things people share legitimately every day. A household shares an
# address and a laptop; an office, a university or a service-centre kiosk puts
# hundreds of unrelated citizens behind one IP and one machine. Shared alone,
# these justify a closer look and nothing more.
#
# STRONG: things that should be unique to one human being. Two genuine
# applicants do not hold the same identity document, and they do not share a
# mobile number. One of these shared across identities is worth more than three
# weak ones, so strength is judged by WHICH attributes are shared, not by how
# many.
WEAK_ATTRIBUTES = {"ip_address", "device_id", "address"}
STRONG_ATTRIBUTES = {"document_hash", "phone"}

# Only IP is dropped when computing cluster membership: it is the one attribute
# broad enough (carrier NAT) to merge genuinely unrelated people into one
# component. Device and address still form links; they are just scored gently.
CLUSTERING_EXCLUDED = {"ip_address"}


class IdentityGraph:
    """Incrementally maintained identity/attribute graph."""

    def __init__(self):
        self.graph = nx.Graph()
        self.blocked_identities = set()

    # -- construction ------------------------------------------------------

    def add_attempt(self, attempt):
        """Add one attempt's identity and its shared attributes to the graph."""
        identity = attempt.get("claimed_user_ref")
        if not identity:
            return

        identity_node = ("identity", identity)
        self.graph.add_node(identity_node, kind="identity", label=identity)

        for attribute in LINK_ATTRIBUTES:
            value = attempt.get(attribute)
            if not value:
                continue
            attribute_node = ("attr", attribute, str(value))
            self.graph.add_node(
                attribute_node, kind=attribute,
                label=self._short_label(attribute, str(value)),
                weak=attribute in WEAK_ATTRIBUTES,
            )   # 'weak' drives how the analyst view colours the edge
            self.graph.add_edge(identity_node, attribute_node)

        if attempt.get("decision") == config.DECISION_BLOCK:
            self.blocked_identities.add(identity)

    def mark_blocked(self, identity):
        if identity:
            self.blocked_identities.add(identity)

    @staticmethod
    def _short_label(attribute, value):
        if attribute == "document_hash":
            return "doc:" + value[:8]
        if attribute == "address":
            return value[:24]
        return value

    # -- querying ----------------------------------------------------------

    def cluster(self, identity, strong_only=True):
        """
        Return the identities sharing attributes with this one.

        With strong_only, links formed purely through a shared IP are ignored,
        because a shared IP is normal for families, offices and carrier NAT and
        would otherwise merge unrelated citizens into one giant false cluster.
        """
        identity_node = ("identity", identity)
        if identity_node not in self.graph:
            return set()

        if strong_only:
            excluded = [
                node for node, data in self.graph.nodes(data=True)
                if node[0] == "attr" and node[1] in CLUSTERING_EXCLUDED
            ]
            view = self.graph.subgraph(
                [node for node in self.graph.nodes if node not in excluded]
            )
        else:
            view = self.graph

        if identity_node not in view:
            return {identity}

        component = nx.node_connected_component(view, identity_node)
        return {node[1] for node in component if node[0] == "identity"}

    def shared_attributes(self, identity):
        """Which attributes of this identity are shared with someone else."""
        identity_node = ("identity", identity)
        if identity_node not in self.graph:
            return []

        shared = []
        for attribute_node in self.graph.neighbors(identity_node):
            others = [
                node for node in self.graph.neighbors(attribute_node)
                if node != identity_node
            ]
            if others:
                shared.append({
                    "attribute": attribute_node[1],
                    "value": attribute_node[2],
                    "shared_with": sorted(node[1] for node in others),
                })
        return shared

    def cluster_binding_kinds(self, identity):
        """
        Which attribute TYPES bind this identity's whole cluster together —
        not just the ones this one identity happens to share directly.

        A ring built from pairwise overlaps (A and B share a phone, B and C
        share a device, C and D share an address) is one connected cluster
        of four, but no single member's OWN direct shares reveal that: A's
        `shared_attributes` shows only "phone". The cluster as a whole is
        still held together by three independent identifier types, which is
        exactly the evidence the cross-record rule is meant to catch, so it
        has to be measured across the cluster, not per member.
        """
        kinds = set()
        for member in self.cluster(identity):
            for item in self.shared_attributes(member):
                if item["attribute"] not in CLUSTERING_EXCLUDED:
                    kinds.add(item["attribute"])
        return kinds

    def device_identity_count(self, device_id):
        """How many distinct identities have used this device."""
        if not device_id:
            return 0
        node = ("attr", "device_id", str(device_id))
        if node not in self.graph:
            return 0
        return sum(1 for n in self.graph.neighbors(node) if n[0] == "identity")

    def cluster_has_blocked(self, identity):
        cluster = self.cluster(identity)
        return bool(cluster & self.blocked_identities - {identity})

    # -- visualisation -----------------------------------------------------

    def to_vis_payload(self, identity=None, limit=180):
        """
        Export nodes and edges for the dashboard's network view.

        When an identity is given, only its cluster is exported - a full graph
        of a thousand attempts is unreadable and slow to render in a browser.
        """
        if identity:
            members = self.cluster(identity)
            wanted = set()
            for member in members:
                member_node = ("identity", member)
                if member_node not in self.graph:
                    continue
                wanted.add(member_node)
                # Only attributes that ACTUALLY connect two or more identities
                # are drawn. An attribute touching a single identity is a
                # property of that record, not a link, and rendering it buries
                # the four edges that matter under forty that do not - which is
                # exactly what the first version of this view did.
                for neighbour in self.graph.neighbors(member_node):
                    if neighbour[0] != "attr":
                        continue
                    if neighbour[1] in CLUSTERING_EXCLUDED:
                        continue
                    shared_by = sum(
                        1 for n in self.graph.neighbors(neighbour)
                        if n[0] == "identity"
                    )
                    if shared_by >= 2:
                        wanted.add(neighbour)
            view = self.graph.subgraph(wanted)
        else:
            view = self.graph

        nodes, edges = [], []
        def public_id(node):
            return hashlib.sha256((config.SECRET_KEY + repr(node)).encode()).hexdigest()[:24]

        ordered = sorted(view.nodes(data=True), key=lambda item: (
            0 if item[0] == ("identity", identity) else 1, item[0]))
        for index, (node, data) in enumerate(ordered):
            if index >= limit:
                break
            node_id = public_id(node)
            is_identity = node[0] == "identity"
            label = data.get("label", node[-1])
            if not is_identity and node[1] in ("phone", "address"):
                label = security.mask_pii(node[-1])
            nodes.append({
                "id": node_id,
                "label": label,
                "group": "identity" if is_identity else node[1],
                "blocked": is_identity and node[1] in self.blocked_identities,
                "focus": is_identity and node[1] == identity,
            })

        present = {n["id"] for n in nodes}
        for source, target in view.edges():
            source_id, target_id = public_id(source), public_id(target)
            if source_id in present and target_id in present:
                edges.append({"from": source_id, "to": target_id})

        shared = self.shared_attributes(identity) if identity else []
        links = [{"attribute": item["attribute"],
                  "strength": "strong" if item["attribute"] in STRONG_ATTRIBUTES else "weak",
                  "identity_count": len(item["shared_with"])}
                 for item in shared if item["attribute"] not in CLUSTERING_EXCLUDED]
        return {"nodes": nodes, "edges": edges, "links": links,
                "truncated": len(view) > len(nodes),
                "identity_count": len(self.cluster(identity)) if identity else 0,
                "explanation": "Current links from all recorded attempts, not a snapshot at scoring time. "
                    "IP-only links are excluded, matching the scoring graph. "
                    "A shared device or address can be legitimate; phone and exact-document links carry more weight. "
                    "A link alone is not proof of fraud. The stored reason chain explains the original assessment."}


def build_from_db(conn):
    """Rebuild the graph from persisted attempts, e.g. after a restart."""
    graph = IdentityGraph()
    rows = conn.execute(
        "SELECT claimed_user_ref, device_id, ip_address, phone, address,"
        " document_hash, decision FROM attempts ORDER BY id ASC"
    ).fetchall()
    for row in rows:
        graph.add_attempt(dict(row))
    return graph
