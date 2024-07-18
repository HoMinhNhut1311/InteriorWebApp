package com.hominhnhut.WMN_BackEnd.service.impl;

import com.hominhnhut.WMN_BackEnd.domain.enity.Category;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.repository.CategoryRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.CategoryService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CategoryServiceImpl implements CategoryService {

    CategoryRepository categoryRepository;
    @Override
    public Category saveCategory(Category category) {
        return categoryRepository.save(category);
    }

    @Override
    public Category updateCategory(String categoryId, Category category) {
        Category categoryExist = categoryRepository.findById(categoryId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        category.setCategoryId(categoryId);
        return categoryRepository.save(category);
    }

    @Override
    public void deleteCategory(String categoryId) {
        Category categoryExist = categoryRepository.findById(categoryId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        categoryRepository.deleteById(categoryId);
    }

    @Override
    public Set<Category> getAllCategory() {
        return new HashSet<>(categoryRepository.findAll());
    }

    @Override
    public Category getCategoryById(String categoryId) {
        return categoryRepository.findById(categoryId).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
    }
}
