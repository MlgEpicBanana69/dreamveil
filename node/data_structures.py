import json
import math

# A binary tree node that can store a value seperate from its key
class binary_tree_node:
    def __init__(self, key, value=None):
        self.key = key
        self.value = value
        self.left = None
        self.right = None
        self.height = 1

    def __repr__(self):
        return self.dumps()

    def dumps(self):
        return json.dumps([self.key, self.value])

    @staticmethod
    def loads(json_str):
        if json_str == "None" or json_str is None:
            return None
        json_obj = json.loads(json_str)
        assert type(json_obj) == list
        return binary_tree_node(*json_obj)

class AVL:
    def __init__(self):
        self.tree = None

    def _find(self, root, key):
        """Finds and returns the node of a given key in the tree. Returns None if does not exist"""
        if root is not None:
            if key > root.key:
                return self._find(root.right, key)
            elif key < root.key:
                return self._find(root.left, key)
            else:
                return root
        else:
            # Could not find key in tree
            return None

    def find(self, key):
        return self._find(self.tree, key)

    def _insert(self, root, node):
        if self.tree is None:
            self.tree = node
            return

        if root is None:
            return node

        if node.key > root.key:
            root.right = self._insert(root.right, node)
        elif node.key < root.key:
            root.left = self._insert(root.left, node)
        else:
            root.value = node.value

        root.height = 1 + max(self.get_height(root.left), self.get_height(root.right))

        balance_factor = self.get_balance(root)

        out = root
        if balance_factor > 1:
            if root.right.left is not None:
                temp = root.right
                root.right = root.right.left
                root.right.right = temp
                root.right.right.left = None
            out = self.left_rotate(root)
        elif balance_factor < -1:
            if root.left.right is not None:
                temp = root.left
                root.left = root.left.right
                root.left.left = temp
                root.left.left.right = None
            out = self.right_rotate(root)
        if root == self.tree:
            self.tree = out
        return out

    def insert(self, node):
        self._insert(self.tree, node)

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
        if root.right is not None:
            root.right.height = 1 + max(self.get_height(root.right.right), self.get_height(root.right.left))
        root.height = 1 + max(self.get_height(root.right), self.get_height(root.left))
        return root

    def right_rotate(self, root):
        temp = root
        root = root.left
        root.right = temp
        root.right.left = None

        root.right.height = 1 + max(self.get_height(root.right.left), self.get_height(root.right.right))
        if root.left is not None:
            root.left.height = 1 + max(self.get_height(root.left.left), self.get_height(root.left.right))
        root.height = 1 + max(self.get_height(root.left), self.get_height(root.right))
        return root

    def get_balance(self, root):
        return self.get_height(root.right) - self.get_height(root.left)

    def dumps(self, curr_parents=None):
        output = ""
        if self.tree is None:
                return ""
        elif self.tree.left is None and self.tree.right is None:
            return self.tree.dumps()

        if curr_parents is None:
            output = f"{str(self.tree.dumps())}"
            curr_parents = [self.tree]
        if curr_parents == len(curr_parents) * [None]:
            return output

        children = []
        for parent in curr_parents:
            if parent is not None:
                output += "\x00" + (parent.left.dumps() if parent.left is not None else "None")
                output += "\x00" + (parent.right.dumps() if parent.right is not None else "None")

                children.append(parent.left)
                children.append(parent.right)
            else:
                output += "\x00None\x00None"
                children.append(None)
                children.append(None)
        next_rec = self.dumps(children)
        if next_rec == "":
            return "\x00"
        elif next_rec == "\x00":
            return output
        else:
            output += next_rec
            return output

    @staticmethod
    def loads(avl_json):
        if avl_json != '':
            all_nodes = [binary_tree_node.loads(node) for node in avl_json.split("\x00")]
            output_tree = AVL()
            output_tree.tree = all_nodes[0]
            for i in range(int(math.log(len(all_nodes), 2))):
                curr_parents = all_nodes[2**i - 1: 2**(i+1) - 1]
                curr_children = all_nodes[2**(i+1) - 1:2**(i+2)-1]
                for parent in curr_parents:
                    if parent is not None:
                        parent.height = 1 + int(math.log(len(all_nodes), 2)) - i
                for child in curr_children:
                    if child is not None:
                        child.height = 1 + int(math.log(len(all_nodes), 2)) - (i + 1)

                for c, child in enumerate(curr_children):
                    parent = curr_parents[c//2]
                    if parent is not None:
                        if c % 2 == 0:
                            parent.left = curr_children[c]
                        else:
                            parent.right = curr_children[c]
            return output_tree
        else:
            return AVL()