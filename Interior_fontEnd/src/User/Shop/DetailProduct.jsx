import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import Detail from "./DetailProductComponent/Detail";
import { findByProductId } from "../../Data/Product/ProductApi";

function DetailProduct() {
  const { productId } = useParams();
  const [product, setProduct] = useState({});
  useEffect(() => {
    if (productId) {
      findByProductId(productId)
        .then((data) => {
          setProduct(data);
        })
        .catch((error) => {
          console.error("Error fetching product:", error);
        });
    }
  }, [productId]);
  return (
    <div>
      <nav className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-12">
              <ol className="breadcrumb mb-0 fs-xs text-gray-400">
                <li className="breadcrumb-item">
                  <a className="text-gray-400" href="index.html">
                    Home
                  </a>
                </li>
                <li className="breadcrumb-item">
                  <a className="text-gray-400" href="shop.html">
                    {product?.categoryName}
                  </a>
                </li>
                <li className="breadcrumb-item active">
                  {product?.productName}
                </li>
              </ol>
            </div>
          </div>
        </div>
      </nav>
      {product && <Detail product={product} key={product.productId} />}
    </div>
  );
}

export default DetailProduct;
