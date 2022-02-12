# A binary node that can store a value seperate from its key
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
    def __init__(self, key):
        self.key = key
        self.children = []
        self.height = 1

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