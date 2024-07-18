package com.hominhnhut.WMN_BackEnd.service.Interface;

import com.hominhnhut.WMN_BackEnd.domain.enity.Category;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public interface CategoryService {

    Category saveCategory(Category category);

    Category updateCategory(String categoryId, Category category);

    void deleteCategory(String categoryId);

    Set<Category> getAllCategory();

    Category getCategoryById(String categoryId);
}
