/**
 * @name Excessively large classes
 * @description Classes with too many methods or fields may violate the Single Responsibility Principle
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/large-class
 * @tags maintainability
 *       design
 */

import java

/**
 * Counts the number of fields and methods in a class that contribute to its responsibility footprint.
 */
int classSize(Class c) {
  result = count(Method m | 
    m.getDeclaringType() = c and
    not m.isConstructor() and
    not m.isStatic() and
    not m.getName().matches("get%") and
    not m.getName().matches("set%") and
    not m.getName().matches("toString") and
    not m.getName().matches("equals") and
    not m.getName().matches("hashCode")
  ) + 
  count(Field f |
    f.getDeclaringType() = c and
    not f.isStatic()
  )
}

from Class c, int size
where
  size = classSize(c) and
  size > 20 and  // Threshold for large class
  not c.isInterface() and
  not c.getFile().getBaseName().matches("%Test.java") and  // Exclude test files
  not c.getFile().getBaseName().matches("%Abstract%.java")  // Exclude abstract base classes
select c, "Class has " + size + " methods and fields, which may indicate too many responsibilities"
