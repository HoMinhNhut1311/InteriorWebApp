import { useEffect, useState } from "react";
import Swal from "sweetalert2";
import { RingLoader } from "react-spinners";
import {
  updateProduct,
  uploadFileToProduct,
} from "../../../Data/Product/ProductApi";
import { getAllCategory } from "../../../Data/Category/Category";

function UpdateProduct({ refresh, detail }) {
  const [product, setProduct] = useState({
    productName: detail.productName,
    productPrice: detail.productPrice,
    productDes: detail.productDes,
    categoryId: detail.categoryId,
    stock:detail.stock,
    mediaFilePath: detail.mediaFilePath
  });
  const productId = detail.productId;
  const [onLoad, setOnLoad] = useState(false);
  const [errors, setErrors] = useState({});
  const [image, setImage] = useState(null); // To store image file
  const [categories, setCategories] = useState([]);

  useEffect(() => {
    getAllCategory().then((res) => setCategories(res));
  }, []);

  const validate = () => {
    const validationErrors = {};

    if (!product.productName.trim()) {
      validationErrors.productName = "Tên sản phẩm không được để trống";
    }

    if (!String(product.productPrice).trim()) {
      validationErrors.productPrice = "Giá không được để trống";
    } else if (isNaN(product.productPrice)) {
      validationErrors.productPrice = "Giá sản phẩm phải là số";
    } else if (Number(product.productPrice) < 1) {
      validationErrors.productPrice = "Giá sản phẩm phải lớn hơn 0";
    } else if (Number(product.productPrice) > 1e9) {
      validationErrors.productPrice = "Giá sản phẩm quá lớn";
    }
    if (Number(product.stock) < 1) {
      validationErrors.stock = "Số lượng sản phẩm phải lớn hơn 0";
    } else if (Number(product.stock) > 1e9) {
      validationErrors.stock = "Số lượng sản phẩm quá lớn";
    }
    return validationErrors;
  };

  const handleChange = (event) => {
    setProduct({
      ...product,
      categoryId: event.target.value,
    });
  };

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      const validImageTypes = ["image/jpeg", "image/png", "image/gif"];
      if (validImageTypes.includes(file.type)) {
        setImage(file);
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationErrors = validate();
    setErrors(validationErrors);

    if (image === null) {
      return Swal.fire({
        title: "Vui lòng chọn file trước khi cập nhật",
        icon: "question",
      });
    } else {
      const fd = new FormData();
      fd.append("image", image);
      uploadFileToProduct(fd, productId);
    }

    if (Object.keys(validationErrors).length === 0) {
      setOnLoad(true);
      try {
        let response;
        response = await updateProduct(product, productId);
        if (response.status === 200 || response.status === 201) {
          Swal.fire({
            title: "Cập nhật thành công!",
            text: `${response.data.productName} -- ${response.data.productPrice} -- ${response.data.categoryName}`,
            icon: "success",
          }).then(() => {
            setProduct({
              productName: "",
              productPrice: 0,
              productDes: "",
              categoryId: "1",
            });
            refresh();
          });
        } else {
          Swal.fire({
            title: "Tạo sản phẩm thất bại!",
            text: `Lỗi : ${response.data.message}`,
            icon: "error",
          });
        }
      } catch (error) {
        Swal.fire({
          title: "Đã xảy ra lỗi!",
          text: error.message,
          icon: "error",
        });
      } finally {
        setOnLoad(false);
      }
    } else {
      setOnLoad(false); // Stop loader if there are validation errors
    }
  };

  return (
    <div className="updateProduct">
      {onLoad && (
        <div className="my-loader-wrapper">
          <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad} />
          </div>
        </div>
      )}

      <div className="form-group">
        <label htmlFor="name" className="form-label">
          Tên sản phẩm
        </label>
        <input
          type="text"
          className="form-control"
          id="name"
          value={product.productName}
          onChange={(e) =>
            setProduct({
              ...product,
              productName: e.target.value,
            })
          }
        />
        {errors.productName && (
          <p className="text-danger">{errors.productName}</p>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="price" className="form-label">
          Giá
        </label>
        <input
          type="number"
          className="form-control"
          id="price"
          value={product.productPrice}
          onChange={(e) =>
            setProduct({
              ...product,
              productPrice: e.target.value,
            })
          }
        />
        {errors.productPrice && (
          <p className="text-danger">{errors.productPrice}</p>
        )}
      </div>
      <div className="form-group">
        <label htmlFor="stock" className="form-label">
          Số lượng
        </label>
        <input
          type="number"
          className="form-control"
          id="stock"
          value={product.stock}
          onChange={(e) =>
            setProduct({
              ...product,
              stock: e.target.value,
            })
          }
        />
        {errors.stock && <p className="text-danger">{errors.stock}</p>}
      </div>
      <div className="form-group">
        <label htmlFor="desc" className="form-label">
          Mô tả
        </label>
        <input
          type="text"
          className="form-control"
          id="desc"
          value={product.productDes}
          onChange={(e) =>
            setProduct({
              ...product,
              productDes: e.target.value,
            })
          }
        />
      </div>

      <div className="form-group">
        <label htmlFor="" className="form-label">
          Thể loại
        </label>
        <select
          value={product.categoryId}
          onChange={handleChange}
          className="form-control my-2"
        >
          {categories.map((category) => (
            <option key={category.categoryId} value={category.categoryId}>
              {category.categoryName}
            </option>
          ))}
        </select>
      </div>

      <div className="form-group">
        <label htmlFor="image" className="form-label">
          Ảnh sản phẩm
        </label>
        <input
          type="file"
          className="form-control"
          id="image"
          accept="image/jpeg, image/png, image/gif"
          onChange={handleFileChange}
        />
      </div>

      <div className="d-flex justify-content-end">
        <button className="btn btn-primary mt-3 p-2" onClick={handleSubmit}>
          Cập nhật
        </button>
      </div>
    </div>
  );
}

export default UpdateProduct;
