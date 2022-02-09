class tree_node:
    def __init__(self, value):
        self.value = value
        self.left = None
        self.right = None
        self.height = 1

class AVL:
    def __init__(self):
        self.tree = None

    def find(self, root, value):
        if root is not None:
            if value > root.value:
                return self.find(root.right, value)
            elif value < root.value:
                return self.find(root.left, value)
            else:
                return root
        else:
            # Could not find value in tree
            return None

    def insert(self, root, value):
        if self.tree is None:
            self.tree = tree_node(value)
            return

        if root is None:
            return tree_node(value)

        if value > root.value:
            root.right = self.insert(root.right, value)
        elif value < root.value:
            root.left = self.insert(root.left, value)
        else:
            raise ValueError(f"Value {value} already in tree!")

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

if __name__ == '__main__':
    avl = AVL()
    avl.insert(avl.tree, 1)
    avl.insert(avl.tree, 10)
    avl.insert(avl.tree, 15)
    avl.insert(avl.tree, 20)
    avl.insert(avl.tree, 13)
    avl.insert(avl.tree, 6)
    avl.insert(avl.tree, 25)
    avl.find(avl.tree, 20)
    print("test")