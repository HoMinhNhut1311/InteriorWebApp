package com.hominhnhut.WMN_BackEnd.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
public enum EnumRole {
    Admin("Admin"),
    Staff("Staff"),
    Teacher("Teacher"),
    User("User")
    ;

    private final String roleName;
}
