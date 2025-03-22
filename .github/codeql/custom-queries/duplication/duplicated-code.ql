/**
 * @name Duplicated code blocks
 * @description Identifies blocks of duplicated code that should be refactored
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/duplicated-code
 * @tags maintainability
 *       readability
 *       duplication
 */

import java
import external.CodeDuplication

/**
 * A location with a block of duplicated code.
 */
class DuplicateBlock extends DuplicateBlock {
  DuplicateBlock() {
    // Only consider blocks of at least 10 statements
    getNumberOfStatements() >= 10
  }
}

/**
 * Gets the location of the source code for a statement.
 */
Location getLocation(Stmt s) {
  result = s.getLocation()
}

/**
 * Gets a describing text for a method.
 */
string describeMethod(Method m) {
  result = m.getDeclaringType().getName() + "." + m.getName()
}

from DuplicateBlock dup, Stmt stmt, Method method
where
  stmt = dup.getAStatement() and
  method = stmt.getEnclosingCallable() and
  not method.getFile().getAbsolutePath().matches("%/test/%") and // Exclude test files
  not method.hasAnnotation("Override") // Exclude overridden methods
select stmt, "This code is duplicated in " + dup.getNumberOfDuplicates() + " other location(s). " +
       "Consider refactoring to eliminate duplication. Found in " + describeMethod(method) + "."
