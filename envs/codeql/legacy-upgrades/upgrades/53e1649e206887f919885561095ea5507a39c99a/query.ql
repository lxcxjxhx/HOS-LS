class TypeDefinition extends @typedefinition {
  string toString() { none() }
}

class TypeReference extends @typereference {
  string toString() { none() }
}

class TypeVariableType extends @typevariabletype {
  string toString() { none() }
}

newtype K = C()

module SymbolEntity = QlBuiltins::NewEntity<K>;

class Symbol extends SymbolEntity::EntityId {
  string toString() { none() }
}

query predicate new_type_definition_symbol(TypeDefinition def, Symbol symbol) { none() }

query predicate new_type_reference_symbol(TypeReference typ, Symbol symbol) { none() }

query predicate new_typevar_reference_symbol(TypeVariableType typ, Symbol symbol) { none() }
