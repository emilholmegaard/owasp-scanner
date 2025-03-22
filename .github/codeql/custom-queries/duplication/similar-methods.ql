/**
 * @name Similar methods
 * @description Identifies methods with similar structure that might be candidates for refactoring
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id java/similar-methods
 * @tags maintainability
 *       duplication
 */

import java

/**
 * Computes a simplified structural hash for a method body.
 * This focuses on the structure rather than variable names or specific values.
 */
string methodStructuralHash(Method m) {
  exists(string hash |
    hash = concat(Stmt s |
      s.getEnclosingCallable() = m and
      // Include only the structure-defining statement types
      (
        s instanceof IfStmt or
        s instanceof ForStmt or
        s instanceof WhileStmt or
        s instanceof DoStmt or
        s instanceof TryStmt or
        s instanceof SwitchStmt or
        s instanceof ReturnStmt or
        s instanceof ThrowStmt
      )
      |
      s.getClass().getName(), ", " order by s.getLocation().getStartLine()
    ) and
    
    // Add method signature shape to the hash
    result = m.getReturnType() + ":" + 
             m.getNumberOfParameters() + ":" +
             count(Stmt s | s.getEnclosingCallable() = m) + ":" +
             hash
  )
}

/**
 * Gets a normalized name for a method without common prefixes.
 */
string getNormalizedMethodName(Method m) {
  exists(string name | 
    name = m.getName() and
    if name.matches("get%")
    then result = name.substring(3, name.length())
    else if name.matches("set%")
    then result = name.substring(3, name.length())
    else if name.matches("is%")
    then result = name.substring(2, name.length())
    else result = name
  )
}

from Method m1, Method m2, string hash
where
  hash = methodStructuralHash(m1) and
  hash = methodStructuralHash(m2) and
  m1 != m2 and
  // Methods should have at least 5 statements to be considered
  count(Stmt s | s.getEnclosingCallable() = m1) >= 5 and
  // Methods in the same class or in different classes but with similar names
  (
    m1.getDeclaringType() = m2.getDeclaringType() or
    getNormalizedMethodName(m1) = getNormalizedMethodName(m2)
  ) and
  // Avoid reporting both (A,B) and (B,A)
  m1.getLocation().getStartLine() < m2.getLocation().getStartLine() and
  // Exclude test files
  not m1.getFile().getAbsolutePath().matches("%/test/%") and
  not m2.getFile().getAbsolutePath().matches("%/test/%")
select m1, "Method is structurally similar to " + m2.getDeclaringType().getName() + "." + 
       m2.getName() + ". Consider refactoring to eliminate duplication."
