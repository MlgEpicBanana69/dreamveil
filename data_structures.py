# A binary node that can store a value seperate from its key
import json

class binary_tree_node:
    def __init__(self, key, value=None):
        self.key = key
        self.value = value
        self.left = None
        self.right = None
        self.height = 1

class AVL:
    def __init__(self):
        self.tree = None

    def find(self, root, key):
        """Finds and returns the node of a given key in the tree. Returns None if does not exist"""
        if root is not None:
            if key > root.key:
                return self.find(root.right, key)
            elif key < root.key:
                return self.find(root.left, key)
            else:
                return root
        else:
            # Could not find key in tree
            return None

    def insert(self, root, node:binary_tree_node):
        if self.tree is None:
            self.tree = node
            return

        if root is None:
            return node

        if node.key > root.key:
            root.right = self.insert(root.right, node.key)
        elif node.key < root.key:
            root.left = self.insert(root.left, node.key)
        else:
            root.value = node.value

        root.height = 1 + max(self.get_height(root.left), self.get_height(root.right))

        balance_factor = self.get_balance(root)

        out = root
        if balance_factor > 1:
            if root.left is not None:
                out = self.right_rotate(root)
            else:
                out = self.left_rotate(root)
        elif balance_factor < -1:
            if root.right is not None:
                out = self.right_rotate(root)
            else:
                out = self.left_rotate(root)
        if root == self.tree:
            self.tree = out
        return out

    def get_height(self, root):
        if root is None:
            return 0
        return root.height

    def left_rotate(self, root):
        temp = root
        root = root.right
        root.left = temp
        root.left.right = None

        root.left.height = 1 + max(self.get_height(root.left.right), self.get_height(root.left.left))
        root.right.height = 1 + max(self.get_height(root.right.right), self.get_height(root.right.left))
        root.height = 1 + max(self.get_height(root.right), self.get_height(root.left))
        return root

    def right_rotate(self, root):
        temp = root
        root = root.left
        root.right = temp
        root.right.left = None

        root.right.height = 1 + max(self.get_height(root.right.left), self.get_height(root.right.right))
        root.left.height = 1 + max(self.get_height(root.left.left), self.get_height(root.left.right))
        root.height = 1 + max(self.get_height(root.left), self.get_height(root.right))
        return root

    def get_balance(self, root):
        return self.get_height(root.right) - self.get_height(root.left)

class multifurcasting_node:
    def __init__(self, value):
        self.value = value
        self.children = []
        self.height = 1

    def to_list(self):
        return [self.value, [child.to_list() for child in self.children]]

class multifurcasting_tree:
    def __init__(self, root=None):
        self.tree = root

    def insert(self, val, prev_val, root=None):
        # CONTINUE FROM HERE
        # TODO: ADD A TRACE/SEARCH FUNCTION
        if self.tree is None:
            self.tree = multifurcasting_node(val)
            return

        if root is None:
            root = self.tree

        if root.value == prev_val:
            root.children.append(multifurcasting_node(val))
            return root

        if len(root.children) == 0:
            return

        for child in root.children:
            result = self.insert(val, prev_val, child)
            if result is not None:
                break
        return result

    def trace(self, val, root=None, result=[]):
        if root is None:
            root = self.tree
        
        if self.tree is None:
            return
        if root.value == val:
            return root

        for child in root.children:
            output = self.trace(val, child, result + [child])
            if output is not None:
                return result + [child]
        return None

    def calculate_height(self):
        height_sum = 0
        for child in self.children:
            height_sum += child.get_height()
        self.height = 1 + height_sum
        return self.height

    def get_highest_child(self):
        if len(self.children) == 0:
            return False
        highest_child = self.children[0]
        for child in self.children[1::]:
            if child.height > highest_child.height:
                highest_child = child
        return highest_child

    def json_dumps_tree(self):
        return str(self.tree.to_list())

    def __repr__(self):
        return self.json_dumps_tree()

    @staticmethod
    def json_loads_tree(json_str):
        obj = json.loads(json_str)
        return multifurcasting_tree(multifurcasting_tree.peel_json_object(obj))
    @staticmethod
    def peel_json_object(json_obj):
        #[ 7, [ [15, []], [14, []] ] ]
        if len(json_obj[1]) == 0:
            return multifurcasting_node(json_obj[0])

        root = multifurcasting_node(json_obj[0])
        for peel in json_obj[1]:
            root.children.append(multifurcasting_tree.peel_json_object(peel))
        return root