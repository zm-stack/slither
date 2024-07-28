from typing import Set, List, TYPE_CHECKING, Dict

from slither.core.variables import Variable
from slither.slithir.variables import Constant
from slither.slithir.operations import OperationWithLValue, Phi

if TYPE_CHECKING:
    from slither.core.cfg.node import Node


def intersection_predecessor(node: "Node") -> Set["Node"]:
    if not node.fathers:
        return set()

    ret = node.fathers[0].dominators
    for pred in node.fathers[1:]:
        ret = ret.intersection(pred.dominators)
    if not any(father.is_reachable for father in node.fathers):
        return set()

    ret = set()
    for pred in node.fathers:
        ret = ret.union(pred.dominators)

    for pred in node.fathers:
        if pred.is_reachable:
            ret = ret.intersection(pred.dominators)
    return ret


def intersection_successor(node: "Node") -> Set["Node"]:
    if not node.sons:
        return set()

    ret = node.sons[0].post_dominators
    for succ in node.sons[1:]:
        ret = ret.intersection(succ.post_dominators)
    if not any(son.is_reachable for son in node.sons):
        return set()

    ret = set()
    for succ in node.sons:
        ret = ret.union(succ.post_dominators)

    for succ in node.sons:
        if succ.is_reachable:
            ret = ret.intersection(succ.post_dominators)
    return ret


def _compute_dominators(nodes: List["Node"]) -> None:
    changed = True

    while changed:
        changed = False

        for node in nodes:
            new_set = intersection_predecessor(node).union({node})
            if new_set != node.dominators:
                node.dominators = new_set
                changed = True


def _compute_post_dominators(nodes: List["Node"]) -> None:
    changed = True

    while changed:
        changed = False

        for node in nodes:
            new_set = intersection_successor(node).union({node})
            if new_set != node.post_dominators:
                node.post_dominators = new_set
                changed = True

    exit_nodes: Set[Node] = set()
    for node in nodes:
        if len(node.post_dominators) == 1:
            exit_nodes.add(node)
    # We have multiple exit point
    # we need to add a fake node as root to have a post dominator tree and not a forest
    # if len(exit_nodes) > 1:
    #    fake_node = Node(NodeType.OTHER_ENTRYPOINT, 10000, nodes[0].function, nodes[0].function.file_scope)
    #    for node in nodes:
    #        node.post_dominators.add(fake_node)


def _compute_immediate_dominators(nodes: List["Node"]) -> None:
    for node in nodes:
        idom_candidates = set(node.dominators)
        idom_candidates.remove(node)

        if len(idom_candidates) == 1:
            idom = idom_candidates.pop()
            node.immediate_dominator = idom
            # idom.dominator_successors.add(node)
            idom.dominator_successors.append(node)
            continue

        # all_dominators contain all the dominators of all the node's dominators
        # But self inclusion is removed
        # The idom is then the only node that in idom_candidate that is not in all_dominators
        all_dominators = set()
        for d in idom_candidates:
            # optimization: if a node is already in all_dominators, then
            # its dominators are already in too
            if d in all_dominators:
                continue
            all_dominators |= d.dominators - {d}

        idom_candidates = all_dominators.symmetric_difference(idom_candidates)
        assert len(idom_candidates) <= 1
        if idom_candidates:
            idom = idom_candidates.pop()
            node.immediate_dominator = idom
            # idom.dominator_successors.add(node)
            idom.dominator_successors.append(node)


def _compute_immediate_post_dominators(nodes: List["Node"]) -> None:
    for node in nodes:
        ipdom_candidates = set(node.post_dominators)
        ipdom_candidates.remove(node)

        if len(ipdom_candidates) == 1:
            ipdom = ipdom_candidates.pop()
            node.immediate_post_dominator = ipdom
            ipdom.post_dominator_successors.add(node)
            node.post_dominator_predecessors.add(ipdom)
            continue

        # all_dominators contain all the dominators of all the node's dominators
        # But self inclusion is removed
        # The idom is then the only node that in idom_candidate that is not in all_dominators
        all_pdominators = set()
        for d in ipdom_candidates:
            # optimization: if a node is already in all_dominators, then
            # its dominators are already in too
            if d in all_pdominators:
                continue
            all_pdominators |= d.post_dominators - {d}

        ipdom_candidates = all_pdominators.symmetric_difference(ipdom_candidates)
        assert len(ipdom_candidates) <= 1
        if ipdom_candidates:
            ipdom = ipdom_candidates.pop()
            node.immediate_post_dominator = ipdom
            ipdom.post_dominator_successors.add(node)
            node.post_dominator_predecessors.add(ipdom)


def compute_dominators(nodes: List["Node"]) -> None:
    """
    Naive implementation of Cooper, Harvey, Kennedy algo
    See 'A Simple,Fast Dominance Algorithm'

    Compute strict domniators
    """

    for n in nodes:
        n.dominators = set(nodes)
        n.post_dominators = set(nodes)

    _compute_post_dominators(nodes)
    _compute_dominators(nodes)
    _compute_immediate_dominators(nodes)
    _compute_immediate_post_dominators(nodes)


def compute_control_dependent(nodes: List["Node"]):
    for node in nodes:
        for son in node.sons:
            if son not in node.post_dominators:
                # For every node that is not post dominated by "node"
                # we move upwards in the post dominator tree until the node found is the "node"'s parent in the tree
                # each node in the path is control dependent on "node"
                def _mark_dependent(n: "Node", seen: Set["Node"]):
                    if n in seen:
                        return
                    seen.add(n)
                    n.control_dependent_on.add(node)
                    node.control_dependent.add(n)
                    for post_dom_prec in n.post_dominator_predecessors:
                        if (
                            post_dom_prec in node.post_dominator_predecessors
                            or post_dom_prec == node
                        ):
                            continue
                        _mark_dependent(post_dom_prec, seen)

                _mark_dependent(son, set())


def compute_data_dependencies(nodes: List["Node"]):
    from slither.core.cfg.node import NodeType

    var_decl_to_node: Dict[Variable, Node] = {}
    var_to_phi: Dict[Variable, List[Variable]] = {}
    # Precompute information
    for node in nodes:
        if node.type == NodeType.ENTRYPOINT:
            for ir in node.irs_ssa:
                from slither.slithir.variables.state_variable import StateIRVariable

                if isinstance(ir.lvalue, StateIRVariable):
                    var_decl_to_node[ir.lvalue] = node
                    # Needed to initialize the ssa variable corresponding to the current state variable value
                    # possibly wrongly initialize other ssa vars to this node but will be fixed later
                    for rval in ir.rvalues:
                        var_decl_to_node[rval] = node
                    var_to_phi[ir.lvalue] = ir.rvalues

        if node.type == NodeType.VARIABLE and node.expression is None:
            var_decl_to_node[node.variable_declaration_ssa] = node

        for ir in node.irs_ssa:
            if isinstance(ir, Phi) and len(ir.rvalues) != 0:
                if ir.lvalue:
                    var_to_phi[ir.lvalue] = ir.rvalues
                    var_decl_to_node[ir.lvalue] = node
            elif isinstance(ir, OperationWithLValue):
                var_decl_to_node[ir.lvalue] = node

    for node in nodes:
        for ir in node.irs_ssa:
            if isinstance(ir, Phi):
                continue

            for var_read in ir.read:
                if isinstance(var_read, Variable) and not isinstance(var_read, Constant):
                    if var_read in var_to_phi:
                        # recursion to check if var in var_to_phi
                        dependent_vars = []
                        dependent_vars.append(var_read)
                        changed = True
                        while changed:
                            changed = False
                            for var in dependent_vars:
                                if var in var_to_phi:
                                    changed = True
                                    dependent_vars.remove(var)
                                    for var_in_phi in var_to_phi[var]:
                                        dependent_vars.append(var_in_phi)

                        for var in dependent_vars:
                            declaration_node = var_decl_to_node.get(var)
                            declaration_node.data_dependent.add(node)
                            node.data_dependent_on.add(declaration_node)
                    else:
                        declaration_node = var_decl_to_node.get(var_read)
                        declaration_node.data_dependent.add(node)
                        node.data_dependent_on.add(declaration_node)


def compute_dominance_frontier(nodes: List["Node"]) -> None:
    """
    Naive implementation of Cooper, Harvey, Kennedy algo
    See 'A Simple,Fast Dominance Algorithm'

    Compute dominance frontier
    """
    from slither.core.cfg.node import NodeType

    for node in nodes:
        if len(node.fathers) >= 2:
            for father in node.fathers:
                if not father.is_reachable:
                    continue
                runner = father
                # Corner case: if there is a if without else
                # we need to add update the conditional node
                if (
                    runner == node.immediate_dominator
                    and runner.type == NodeType.IF
                    and node.type == NodeType.ENDIF
                ):
                    runner.dominance_frontier = runner.dominance_frontier.union({node})
                while runner != node.immediate_dominator:
                    runner.dominance_frontier = runner.dominance_frontier.union({node})
                    assert runner.immediate_dominator
                    runner = runner.immediate_dominator
