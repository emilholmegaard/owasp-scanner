/**
 * @name High complexity methods
 * @description Methods with high cyclomatic complexity are difficult to test and maintain
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/high-cyclomatic-complexity
 * @tags maintainability
 *       testability
 */

import java

/**
 * Calculate cyclomatic complexity for a callable.
 * Each branch point (if, while, for, case, catch, ?:) adds 1 to complexity.
 */
int cyclomaticComplexity(Callable c) {
  result = 1 + count(Stmt s |
    s.getEnclosingCallable() = c and
    (
      s instanceof IfStmt or
      s instanceof WhileStmt or
      s instanceof ForStmt or
      s instanceof EnhancedForStmt or
      s instanceof SwitchCase or
      s instanceof CatchClause or
      s instanceof ConditionalExpr
    )
  )
}

from Callable c, int complexity
where 
  complexity = cyclomaticComplexity(c) and
  complexity > 10 and  // Threshold for high complexity
  c.getNumberOfLines() > 20  // Ignore very small methods
select c, "Method has high cyclomatic complexity (" + complexity + "). Consider refactoring for improved maintainability."
