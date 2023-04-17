
class JSONAttributeExtractor():

    # initialize extractor
    def __init__(self, file):
        # save data
        self.data = json.loads(file)
        # attributes
        self.attributes = {}

    # extract string metadata
    def extract_string_metadata(self):
        return {
            'string_paths': self.data["strings"]["paths"],
            'string_urls': self.data["strings"]["urls"],
            'string_registry': self.data["strings"]["registry"],
            'string_MZ': self.data["strings"]["MZ"]
        }

    # extract attributes
    def extract(self):

        # get general info
        self.attributes.update({
            "size": self.data["general"]["size"], 
            "virtual_size": self.data["general"]["vsize"],
            "has_debug": self.data["general"]["has_debug"], 
            "imports": self.data["general"]["imports"],
            "exports": self.data["general"]["exports"],
            "has_relocations": self.data["general"]["has_relocations"],
            "has_resources": self.data["general"]["has_resources"],
            "has_signature": self.data["general"]["has_signature"],
            "has_tls": self.data["general"]["has_tls"],
            "symbols": self.data["general"]["symbols"],
        })

        # get header info
        self.attributes.update({
            "timestamp": self.data["header"]["coff"]["timestamp"],
            # NOTE: Machine is a string, we need to transform it in a categorical feature
            # https://scikit-learn.org/stable/modules/preprocessing.html#encoding-categorical-features
            "machine": self.data["header"]["coff"]["machine"],
            # TODO: NFS only
            "numberof_sections": len(self.data["section"]["sections"]),
            "characteristics_list": " ".join(self.data["header"]["coff"]["characteristics"])
        })

       # get optional header
        self.attributes.update({
            "dll_characteristics_list": " ".join(self.data["header"]["optional"]["dll_characteristics"]),
            "magic": self.data["header"]["optional"]["magic"],
            # EMBER only
            "major_image_version": self.data["header"]["optional"]["major_image_version"],
            # EMBER only
            "minor_image_version": self.data["header"]["optional"]["minor_image_version"],
            # EMBER only
            "major_linker_version": self.data["header"]["optional"]["major_linker_version"],
            # EMBER only
            "minor_linker_version": self.data["header"]["optional"]["minor_linker_version"],
            # EMBER only
            "major_operating_system_version": self.data["header"]["optional"]["major_operating_system_version"],
            # EMBER only
            "minor_operating_system_version": self.data["header"]["optional"]["minor_operating_system_version"],
            # EMBER only
            "major_subsystem_version": self.data["header"]["optional"]["major_subsystem_version"],
            # EMBER only
            "minor_subsystem_version": self.data["header"]["optional"]["minor_subsystem_version"],
            "sizeof_code": self.data["header"]["optional"]["sizeof_code"],
            "sizeof_headers": self.data["header"]["optional"]["sizeof_headers"],
            # EMBER only
            "sizeof_heap_commit": self.data["header"]["optional"]["sizeof_heap_commit"]
        })

        # get string metadata
        # EMBER only
        self.attributes.update(self.extract_string_metadata())

        # get imported libraries and functions
        self.libraries = " ".join([item for sublist in self.data["imports"].values() for item in sublist])
        self.libraries = " {} ".format(self.libraries)
        self.functions = " ".join(self.data["imports"].keys())
        self.functions = " {} ".format(self.functions)
        self.attributes.update({"functions": self.functions, "libraries": self.libraries})

        # get exports
        self.exports = " ".join(self.data["exports"])
        self.attributes.update({"exports_list": self.exports})

        # get label
        self.label = self.data["label"]
        self.attributes.update({"label": self.label})

        return(self.attributes)

test = JSONAttributeExtractor("ember")