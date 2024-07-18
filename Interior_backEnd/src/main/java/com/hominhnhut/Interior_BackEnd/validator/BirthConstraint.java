package com.hominhnhut.WMN_BackEnd.validator;

import com.hominhnhut.WMN_BackEnd.validator.Validate.BirthValidate;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotNull;

import java.lang.annotation.Documented;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({FIELD })
@Retention(RUNTIME)
@Constraint(validatedBy = {BirthValidate.class})
public @interface BirthConstraint {


    String message() default "{}";

    int min();

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };

}
