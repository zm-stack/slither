"""
    CK Metrics are a suite of six software metrics proposed by Chidamber and Kemerer in 1994.
    These metrics are used to measure the complexity of a class.

"""
import math
from collections import OrderedDict
from slither.printers.abstract_printer import AbstractPrinter
from slither.slithir.variables.temporary import TemporaryVariable
from slither.utils.myprettytable import make_pretty_table
from typing import TYPE_CHECKING, List, Tuple
from slither.slithir.operations.high_level_call import HighLevelCall


def compute_metrics(contracts):
    """
    Compute CK metrics of a contract
    Args:
        contracts(list): list of contracts
    Returns:
        a tuple of (metrics1, metrics2, metrics3)
        metrics1["contract name"] = {
            "public": mut/view/pure,
            "external":mut/view/pure,
            "internal":mut/view/pure,
            "private":mut/view/pure,
        }
        metrics2["contract name"] = {
            "state_variables":int,
            "constants":int,
            "immutables":int,
        }
        metrics3["contract name"] = {
            "external_mutating":int,
            "no_auth":int,
            "no_modifiers":int,
            "rfc":int,
            "external_calls":int,
        }

        RFC is counted as follows:
        +1 for each public or external fn
        +1 for each public getter
        +1 for each UNIQUE external call

    """
    metrics1 = {}
    metrics2 = {}
    metrics3 = {}
    for c in contracts:
        (state_variables, constants, immutables, public_getters) = count_variables(c)
        rfc = public_getters  # add 1 for each public getter
        metrics1[c.name] = {
            "public": {"mutating": 0, "view": 0, "pure": 0},
            "external": {"mutating": 0, "view": 0, "pure": 0},
            "internal": {"mutating": 0, "view": 0, "pure": 0},
            "private": {"mutating": 0, "view": 0, "pure": 0},
        }
        metrics2[c.name] = {
            "state_variables": state_variables,
            "constants": constants,
            "immutables": immutables,
        }
        metrics3[c.name] = {
            "external_mutating": 0,
            "no_auth": 0,
            "no_modifiers": 0,
            "rfc": 0,
            "external_calls": 0,
        }
        for func in c.functions:
            if func.name == "constructor":
                continue
            pure = func.pure
            view = not pure and func.view
            mutating = not pure and not view
            external = func.visibility == "external"
            public = func.visibility == "public"
            internal = func.visibility == "internal"
            private = func.visibility == "private"
            mutatability = "mutating" if mutating else "view" if view else "pure"
            epm = external or public and mutating
            external_public_mutating = epm
            external_no_auth = epm and no_auth(func)
            external_no_modifiers = epm and len(func.modifiers) == 0
            if external or public:
                rfc += 1

            high_level_calls = [
                ir for node in func.nodes for ir in node.irs_ssa if isinstance(ir, HighLevelCall)
            ]

            # convert irs to string with target function and contract name
            external_calls = [
                f"{high_level_calls[0].function_name}{high_level_calls[0].destination.contract.name}"
                for high_level_calls[0] in high_level_calls
            ]
            rfc += len(set(external_calls))
            metrics1[c.name]["public"][mutatability] += 1 if public else 0
            metrics1[c.name]["external"][mutatability] += 1 if external else 0
            metrics1[c.name]["internal"][mutatability] += 1 if internal else 0
            metrics1[c.name]["private"][mutatability] += 1 if private else 0

            metrics2[c.name] = {
                "state_variables": state_variables,
                "constants": constants,
                "immutables": immutables,
            }
            metrics3[c.name] = {
                "external_mutating": metrics3[c.name]["external_mutating"]
                + (1 if external_public_mutating else 0),
                "no_auth": metrics3[c.name]["no_auth"] + (1 if external_no_auth else 0),
                "no_modifiers": metrics3[c.name]["no_modifiers"]
                + (1 if external_no_modifiers else 0),
                "rfc": rfc,
                "external_calls": metrics3[c.name]["external_calls"] + len(external_calls),
            }
        metrics1_display = format_metrics1(metrics1)
    return metrics1_display, metrics2, metrics3


def format_metrics1(metrics1):
    metrics1_display = {}
    totals = {
        "public": {"mutating": 0, "view": 0, "pure": 0},
        "external": {"mutating": 0, "view": 0, "pure": 0},
        "internal": {"mutating": 0, "view": 0, "pure": 0},
        "private": {"mutating": 0, "view": 0, "pure": 0},
    }
    for c in metrics1:
        new_metrics = {}
        for key in metrics1[c]:
            values = metrics1[c][key]
            new_metrics[key] = f"{values['mutating']} / {values['view']} / {values['pure']}"
            # update totals
            for k in values:
                totals[key][k] += values[k]
        metrics1_display[c] = new_metrics
    # add totals
    metrics1_display["TOTAL"] = {}
    for key in totals:
        values = totals[key]
        metrics1_display["TOTAL"][
            key
        ] = f"{values['mutating']} / {values['view']} / {values['pure']}"

    return metrics1_display


def count_variables(contract) -> Tuple[int, int, int, int]:
    """Count the number of variables in a contract
    Args:
        contract(core.declarations.contract.Contract): contract to count variables
    Returns:
        Tuple of (state_variable_count, constant_count, immutable_count, public_getter)
    """
    state_variable_count = 0
    constant_count = 0
    immutable_count = 0
    public_getter = 0
    for var in contract.variables:
        if var.is_constant:
            constant_count += 1
        elif var.is_immutable:
            immutable_count += 1
        else:
            state_variable_count += 1
        if var.visibility == "public":
            public_getter += 1
    return (state_variable_count, constant_count, immutable_count, public_getter)


def no_auth(func) -> bool:
    """
    Check if a function has no auth or only_owner modifiers
    Args:
        func(core.declarations.function.Function): function to check
    Returns:
        bool
    """
    for modifier in func.modifiers:
        if "auth" in modifier.name or "only_owner" in modifier.name:
            return False
    return True


class CKMetrics(AbstractPrinter):
    ARGUMENT = "ck"
    HELP = "Computes the CK complexity metrics for each contract"

    WIKI = "https://github.com/trailofbits/slither/wiki/Printer-documentation#ck"

    def output(self, _filename):
        if len(self.contracts) == 0:
            return self.generate_output("No contract found")
        metrics1, metrics2, metrics3 = compute_metrics(self.contracts)
        txt = ""
        # metrics1: function visibility and mutability counts
        txt += "\nCK complexity core metrics 1/3:\n"
        keys = list(metrics1[self.contracts[0].name].keys())
        table1 = make_pretty_table(
            ["Contract", "public", "external", "internal", "private"], metrics1, False
        )
        txt += str(table1) + "\n"

        # metrics2: variable counts
        txt += "\nCK complexity core metrics 2/3:\n"
        keys = list(metrics2[self.contracts[0].name].keys())
        table2 = make_pretty_table(["Contract", *keys], metrics2, True)
        txt += str(table2) + "\n"

        # metrics3: external mutability and rfc
        txt += "\nCK complexity core metrics 3/3:\n"
        keys = list(metrics3[self.contracts[0].name].keys())
        table3 = make_pretty_table(["Contract", *keys], metrics3, True)
        txt += str(table3) + "\n"

        res = self.generate_output(txt)
        res.add_pretty_table(table1, "CK complexity core metrics 1/3")
        res.add_pretty_table(table2, "CK complexity core metrics 2/3")
        res.add_pretty_table(table3, "CK complexity core metrics 3/3")
        self.info(txt)

        return res
