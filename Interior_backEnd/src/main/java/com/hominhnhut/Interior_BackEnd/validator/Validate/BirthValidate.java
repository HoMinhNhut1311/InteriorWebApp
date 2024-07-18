package com.hominhnhut.WMN_BackEnd.validator.Validate;

import com.hominhnhut.WMN_BackEnd.validator.BirthConstraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

public class BirthValidate implements ConstraintValidator<BirthConstraint, LocalDate> {

    private int min;

    @Override
    public boolean isValid(LocalDate value, ConstraintValidatorContext context) {
        if (Objects.isNull(value))
            return true;

        long age = ChronoUnit.YEARS.between(value,LocalDate.now());
        return age >= min;
    }

    @Override
    public void initialize(BirthConstraint constraintAnnotation) {
        min = constraintAnnotation.min();
    }


}
