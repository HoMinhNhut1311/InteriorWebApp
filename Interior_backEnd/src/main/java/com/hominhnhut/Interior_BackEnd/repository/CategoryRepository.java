package com.hominhnhut.WMN_BackEnd.repository;

import com.hominhnhut.WMN_BackEnd.domain.enity.Category;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CategoryRepository extends JpaRepository<Category, String> {
}
