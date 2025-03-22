/**
 * @name Deeply nested control structures
 * @description Methods with deeply nested control structures are difficult to read and maintain
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/deep-nesting
 * @tags maintainability
 *       readability
 */

import java

/**
 * Gets the nesting depth of a statement.
 */
int nestingDepth(Stmt s) {
  // Base case
  s.getParent() instanceof BlockStmt and
  s.getParent().getParent() instanceof Callable and
  result = 0
  or
  // Recursive case for nested control structures
  exists(Stmt parent |
    parent = s.getParent().(BlockStmt).getParent() and
    (
      parent instanceof IfStmt or
      parent instanceof ForStmt or
      parent instanceof EnhancedForStmt or
      parent instanceof WhileStmt or
      parent instanceof DoStmt or
      parent instanceof TryStmt or
      parent instanceof CatchClause or
      parent instanceof SynchronizedStmt
    ) and
    result = nestingDepth(parent) + 1
  )
}

from Stmt s, Callable c, int depth
where
  depth = nestingDepth(s) and
  depth >= 4 and  // Threshold for excessive nesting
  c = s.getEnclosingCallable() and
  (
    s instanceof IfStmt or
    s instanceof ForStmt or
    s instanceof EnhancedForStmt or
    s instanceof WhileStmt or
    s instanceof DoStmt
  )
select s, "Control structure is nested " + depth + " levels deep in " + c.getName() + 
          ". Consider refactoring to improve readability."
