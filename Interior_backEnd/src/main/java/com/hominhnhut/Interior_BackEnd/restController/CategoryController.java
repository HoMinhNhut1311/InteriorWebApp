package com.hominhnhut.WMN_BackEnd.restController;


import com.hominhnhut.WMN_BackEnd.domain.enity.Category;
import com.hominhnhut.WMN_BackEnd.service.Interface.CategoryService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/category")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CategoryController {

        CategoryService categoryService;

        @GetMapping
        public ResponseEntity<
            Set<Category>> findAllCategory() {
            Set<Category> response = categoryService.getAllCategory();
            return ResponseEntity.ok(response);
        }

    @GetMapping("/{id}")
    public ResponseEntity<Category>
                                    findCategoryById(
           @PathVariable("id") String categoryID
    ) {
        Category response = categoryService.getCategoryById(categoryID);
        return ResponseEntity.ok(response);
    }

    @PostMapping
    public ResponseEntity<Category> saveCategory(
            @RequestBody Category category
    ) {
            Category response = categoryService.saveCategory(category);
            return ResponseEntity.ok(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Category> updateCategory(
            @PathVariable("id") String categorId,
            @RequestBody Category category
    ) {
            Category response = categoryService.updateCategory(categorId, category);
            return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCategory (
            @PathVariable("id") String categoryId
    ) {
            categoryService.deleteCategory(categoryId);
            return ResponseEntity.notFound().build();
    }
}
