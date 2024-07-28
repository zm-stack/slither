from slither.printers.abstract_printer import AbstractPrinter
from slither.utils.output import Output


class PostDominator(AbstractPrinter):

    ARGUMENT = "post-dominator"
    HELP = "Export the post dominator tree of each function"

    WIKI = "https://github.com/trailofbits/slither/wiki/Printer-documentation#post-dominator"

    def output(self, filename: str) -> Output:
        """
        _filename is not used
        Args:
            _filename(string)
        """

        info = ""
        all_files = []
        for contract in self.contracts:
            for function in contract.functions + contract.modifiers:
                if filename:
                    new_filename = f"{filename}-{contract.name}-{function.full_name}.dot"
                else:
                    new_filename = f"post-dominator-{contract.name}-{function.full_name}.dot"
                info += f"Export {new_filename}\n"
                content = function.post_dominator_tree_to_dot(new_filename)
                all_files.append((new_filename, content))

        self.info(info)

        res = self.generate_output(info)
        for filename_result, content in all_files:
            res.add_file(filename_result, content)
        return res
