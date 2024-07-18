import { useEffect, useState } from "react";
import Products from "./Item/Products";
import { getPageProduct } from "../../Data/Product/ProductApi";
import { getAllCategory } from "../../Data/Category/Category";

const PAGE_SIZE = 6;

function Shop() {
  const [products, setProducts] = useState([]); // Initialize as an empty array
  const [selectedCategory, setSelectedCategory] = useState("Tất cả sản phẩm");
  const [selectedCategoryId, setSelectedCategoryId] = useState(0); // To store category ID
  const [selectedFilter, setSelectedFilter] = useState("Lọc theo giá");
  const [categories, setCategories] = useState([]); // Initialize as an empty array
  const [isLoading, setIsLoading] = useState(true);
  const [pagePresent, setPagePresent] = useState(0);
  const [pageSize, setPageSize] = useState();

  const setDataPage = async (size, number, categoryId) => {
    setIsLoading(true);
    const response = await getPageProduct(size, number, categoryId);
    setProducts(response.content);
    setPageSize(response.totalPages);
    setIsLoading(false);
  };

  useEffect(() => {
    const fetchProductsAndCategories = async () => {
      try {
        const productResponse = await getPageProduct(PAGE_SIZE, 0, 0);
        setProducts(productResponse.content);
        const categoryResponse = await getAllCategory();
        setCategories(categoryResponse);
      } finally {
        setIsLoading(false);
      }
    };

    fetchProductsAndCategories();
  }, []);

  const refresh = async () => {
    console.log("Cập nhật lại trang");
    setIsLoading(true);
    setDataPage(PAGE_SIZE, pagePresent, selectedCategoryId);
  };

  useEffect(() => {
    refresh();
  }, []);

  const handleNext = () => {
    setPagePresent((pres) => (pres === pageSize - 1 ? 0 : pres + 1));
  };

  const handlePrev = () => {
    setPagePresent((pres) => (pres === 0 ? pageSize - 1 : pres - 1));
  };

  const handleCategoryChange = (e) => {
    const categoryName = e.target.value;
    setSelectedCategory(categoryName);
    const category = categories.find(
      (cat) => cat.categoryName === categoryName
    );
    setSelectedCategoryId(category ? category.categoryId : 0);
  };

  const handleFilterChange = (e) => {
    setSelectedFilter(e.target.value);
  };

  const filteredProducts = products.sort((a, b) => {
    if (selectedFilter === "Giá từ cao đến thấp") {
      return b.productPrice - a.productPrice;
    } else if (selectedFilter === "Giá từ thấp đến cao") {
      return a.productPrice - b.productPrice;
    } else if (selectedFilter === "Tên sản phẩm từ a - z") {
      return a.productName.localeCompare(b.productName);
    } else if (selectedFilter === "Tên sản phẩm từ z - a") {
      return b.productName.localeCompare(a.productName);
    } else {
      return 0;
    }
  });

  useEffect(() => {
    setDataPage(PAGE_SIZE, pagePresent, selectedCategoryId);
    console.log("Cập nhật Data Page");
  }, [pagePresent, selectedCategoryId]);

  if (isLoading) {
    return (
      <div className="loader">
        <div className="wrapper">
          <div className="circle"></div>
          <div className="line-1"></div>
          <div className="line-2"></div>
          <div className="line-3"></div>
          <div className="line-4"></div>
        </div>
      </div>
    );
  }

  return (
    <section className="py-11">
      <div className="container">
        <div className="row">
          <div className="col-12 col-md-8 col-lg-9">
            <div className="row align-items-center mb-7">
              <div className="col-12 col-md">
                <h3 className="mb-1">Danh sách sản phẩm</h3>
              </div>
              <div className="col-12 col-md-auto">
                <select
                  className="form-select form-select-xs"
                  value={selectedCategory}
                  onChange={handleCategoryChange}
                >
                  <option value="Tất cả sản phẩm">Tất cả sản phẩm</option>
                  {categories.map((category) => (
                    <option
                      key={category.categoryId}
                      value={category.categoryName}
                    >
                      {category.categoryName}
                    </option>
                  ))}
                </select>
              </div>
              <div className="col-12 col-md-auto">
                <select
                  className="form-select form-select-xs"
                  value={selectedFilter}
                  onChange={handleFilterChange}
                >
                  <option value="Lọc theo giá">Lọc theo giá</option>
                  <option value="Giá từ cao đến thấp">
                    Giá từ cao đến thấp
                  </option>
                  <option value="Giá từ thấp đến cao">
                    Giá từ thấp đến cao
                  </option>
                  <option value="Tên sản phẩm từ a - z">
                    Tên sản phẩm từ a - z
                  </option>
                  <option value="Tên sản phẩm từ z - a">
                    Tên sản phẩm từ z - a
                  </option>
                </select>
              </div>
            </div>
            <div className="row">
              {products &&
                filteredProducts.map((product) => (
                  <Products key={product.productId} product={product} />
                ))}
            </div>
          </div>
        </div>
        <div className="col-12 d-flex justify-content-end">
          <button className="buttona button-secondarya" onClick={handlePrev}>
            Trước đó
          </button>
          <div className="numberPage mx-4 text-center m-2 fw-bold fs-5">
            <span className="pagePresent">{pagePresent + 1}</span>/
            <span className="pageSize">{pageSize}</span>
          </div>
          <button className="buttona button-secondarya" onClick={handleNext}>
            Tiếp theo
          </button>
        </div>
      </div>
    </section>
  );
}

export default Shop;
