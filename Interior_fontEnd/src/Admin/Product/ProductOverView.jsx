import { useEffect, useState } from "react";
import Swal from "sweetalert2";
import { RingLoader } from "react-spinners";
import {
  deleteProduct,
  findByProductId,
  getPageProduct,
  getProductsByProductNameContaining,
} from "../../Data/Product/ProductApi";
import CreateProduct from "./Form/CreateProduct";
import ProductSearch from "./Search/ProductSearch";
import UpdateProduct from "./Form/UpdateProduct";

const PAGE_SIZE = 5;

function ProductOverView() {
  const [pagePresent, setPagePresent] = useState(0);
  const [pageSize, setPageSize] = useState();
  const [hasCreate, setHasCreate] = useState(false);
  const [onLoad, setOnLoad] = useState(false);
  const [isUpdate, setIsUpdate] = useState(false);
  const [data, setData] = useState([]);
  const [detail, setDetail] = useState({
    productId: "",
    productName: "",
    productPrice: "",
    productDes: "",
    categoryId: "1",
    stock: ""
  });
  const [keyWord, setKeyWord] = useState("");
  const setDataPage = async (size, number, category) => {
    setOnLoad(true);
    const response = await getPageProduct(size, number, category);
    setData(response.content);
    setPageSize(response.totalPages);
    setOnLoad(false);
  };

  const search = async (productName) => {
    setOnLoad(true);
    const response = await getProductsByProductNameContaining(productName);
    setData(response);
    setOnLoad(false);
  };
  const refresh = async () => {
    console.log("Cập nhật lại trang");
    setOnLoad(true);
    setDataPage(PAGE_SIZE, pagePresent, 0);
  };
  // Begin Trang
  useEffect(() => {
    refresh();
  }, []);
  useEffect(() => {
    console.log(detail); // Đảm bảo in ra giá trị detail mới
  }, [detail]);
  
  // Hàm Next
  const handleNext = () => {
    pagePresent === pageSize - 1
      ? setPagePresent(0)
      : setPagePresent((pres) => pres + 1);
  };

  // Hàm Prev
  const handlePrev = () => {
    pagePresent === 0
      ? setPagePresent(pageSize - 1)
      : setPagePresent((pres) => pres - 1);
  };

  // Bắt sự kiện thay đổi Page hoặc RoleId
  useEffect(() => {
    if (keyWord == "") {
      setDataPage(PAGE_SIZE, pagePresent, 0);
      console.log("Cập nhật Data Page");
    } else {
      search(keyWord);
    }
  }, [pagePresent, keyWord]);

  const handleRemove = (idProd) => {
    deleteProduct(idProd).then((res) => {
      if (res.status === 204) {
        Swal.fire({
          title: "Xóa thành công",
          text: "idProd : " + idProd,
          icon: "success",
        })
          .then(() => refresh())
          .then(() => {
            if (data.length === 1) {
              console.log("gọi");
              handlePrev();
            }
          });
      } else {
        Swal.fire({
          title: "Xóa thất bại",
          text: res.response + " - " + idProd,
          icon: "info",
        });
      }
    });
  };
  const openForm =async (id) => {
   await findByProductId(id)
    .then((product) => {
      const updatedDetail = {
        productId: product.productId,
        productName: product.productName,
        productPrice: product.productPrice,
        productDes: product.productDes,
        categoryId: product.categoryId,
        stock: product.stock,
        mediaFilePath: product.mediaFilePath
      };
      setDetail(updatedDetail);
    })
    .catch((err) => {
      console.log(err);
    });
};

  return (
    <div className="container-fluid">
      {onLoad && (
        <div className="my-loader-wrapper">
          <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad} />
          </div>
        </div>
      )}

      <div className="row gy-4">
        {/* <UserCountCard
          handleRole={handleRole}
          roleData={roleData}
          setRoleData={setRoleData}
        /> */}
        <div className="col-md-3 col-sm-6 text-center d-flex align-items-end">
          <div className="create-user">
            <button
              className="btn btn-outline-light p-3 fw-bold text-uppercase"
              onClick={() => {
                setHasCreate((prev) => !prev);
                setDetail({
                  productId: "",
                  productName: "",
                  productPrice: 0,
                  productDes: "",
                  categoryId: "1",
                });
              }}
            >
              {hasCreate
                ? "Ẩn Form Sản phẩm"
                : "Hiện Form Sản phẩm"}
            </button>
          </div>
        </div>
        {hasCreate && isUpdate == false && (
          <CreateProduct refresh={refresh} key={1} />
        )}
        {isUpdate == true && (
          <UpdateProduct detail={detail} refresh={refresh} key={2} />
        )}
        <div style={{ width: "30%", margin: "auto", float: "right" }}>
          <ProductSearch key={1} setKeyWord={setKeyWord} keyWord={keyWord} />
        </div>
        <div className="col-12">
          <table className="table table-hover text-center">
            <thead>
              <tr className="fw-bold text-danger">
                <th scope="col">STT</th>
                <th scope="col">Tên sản phẩm</th>
                <th scope="col">Giá</th>
                <th scope="col">Tên thể loại</th>
                <th scope="col">Mô tả</th>
                <th scope="col">Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {data.map((product, index) => {
                return (
                  <tr className="hoverTabel" key={index}>
                    <td>{index + 1}</td>
                    <td>{product.productName ?? "Chưa có"}</td>
                    <td>{product.productPrice ?? "Chưa có"}</td>
                    <td>{product.categoryName ?? "Chưa có"}</td>
                    <td>{product.productDes ?? "Chưa có"}</td>
                    <td>
                      <button
                        className="btn btn-danger me-2"
                        onClick={() => handleRemove(product.productId)}
                      >
                        Xóa
                      </button>

                      <button
                        className="btn btn-warning"
                        onClick={() => {
                          openForm(product.productId);
                          setIsUpdate(!isUpdate);
                        }}
                      >
                        {isUpdate ? "Đóng" : "Sửa"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="col-12 d-flex justify-content-end">
          <button className="btn btn-danger" onClick={() => handlePrev()}>
            Trước đó
          </button>
          <div className="numberPage mx-4 text-center m-2 fw-bold fs-5">
            <span className="pagePresent">{pagePresent + 1}</span>/
            <span className="pageSize">{pageSize}</span>
          </div>
          <button className="btn btn-success" onClick={() => handleNext()}>
            Tiếp theo
          </button>
        </div>
      </div>
    </div>
  );
}

export default ProductOverView;
