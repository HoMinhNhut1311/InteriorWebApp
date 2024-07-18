import { useEffect, useState } from "react";
import {
  getProductBestSeller,
  getProductSoldByLocalDate,
} from "../../Data/Revenue/Revenue";
import ChartComponent from "./ChartComponent/ChartComponent";
import { RingLoader } from "react-spinners";
import { getProductsByProductNameContaining } from "../../Data/Product/ProductApi";

function Revenue() {
  const [labels, setLabels] = useState([]);
  const [data, setData] = useState([]);
  const [revenue, setRevenue] = useState([]);
  const [bestSeller, setBestSeller] = useState({});
  const [onLoad, setOnLoad] = useState(false);
  const [name, setName] = useState([]);
  const [date, setDate] = useState(new Date());
  const [total, setTotal] = useState(0);
  const [product, setProduct] = useState([]);
  const getCurrentDate = (d) => {
    const year = d.getFullYear();
    let month = d.getMonth() + 1;
    month = month < 10 ? `0${month}` : month;
    let day = d.getDate();
    day = day < 10 ? `0${day}` : day;
    return `${year}-${month}-${day}`;
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        setOnLoad(true);
        const [revenueProductByDate, revenueProductSeller] = await Promise.all([
          getProductSoldByLocalDate(getCurrentDate(new Date(date))),
          getProductBestSeller(),
        ]);
        setRevenue(revenueProductByDate);
        setBestSeller(revenueProductSeller);
        if (revenueProductByDate && revenueProductByDate.length > 0) {
          const newLabels = revenueProductByDate.map(
            (item) => item.productName
          );
          const newData = revenueProductByDate.map((item) => item.revenue);
          setLabels(newLabels);
          setData(newData);
          setOnLoad(false);
          let sum = newData.reduce((sum, item) => sum + item);
          setTotal(sum);
        } else {
          setLabels("");
          setOnLoad(false);
        }
        const productName = revenueProductSeller.productName;
        setName(productName);
        await getProductsByProductNameContaining(productName).then((res) => {
          console.log(res);
          setProduct(res);
        });
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };
    fetchData();
  }, [date]);

  return (
    <div className="row">
      {onLoad && (
        <div className="my-loader-wrapper">
          <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad} />
          </div>
        </div>
      )}
      <div className="col-8">
        <div
          className="card border border-2 m-5"
          style={{ borderRadius: "15px" }}
        >
          <div className="card-header d-flex justify-content-between align-items-center">
            <span className="text-uppercase text-light">Doanh thu</span>
            <input
              type="date"
              name="dob"
              id="dob"
              className="formbold-form-input"
              style={{ width: "200px" }}
              value={getCurrentDate(new Date(date))}
              onChange={(e) => setDate(e.target.value)}
            />
          </div>
          <div className="card-body">
            <div style={{ width: "100%", overflowX: "auto" }}>
              <div style={{ width: "600px", margin: "0 auto" }}>
                {revenue && <ChartComponent labels={labels} data={data} />}
              </div>
            </div>
            <span className="text-light">Tổng doanh thu: {total} VND</span>
          </div>
        </div>
      </div>
      <div className="col-4">
        <div
          className="card border border-2 m-5"
          style={{ borderRadius: "15px" }}
        >
          <div className="card-header">
            <span className="text-uppercase text-light">
              Sản phẩm có doanh thu cao nhất
            </span>
          </div>
          <div className="card-body">
            <div style={{ width: "100%" }}>
              <div className="cardd mb-7 ms-7">
                <div className="card-img">
                    <a className="card-img-hover" href="#">
                      <img
                        className="card-img-top card-img-back"
                        src={product[0].mediaFilePath}
                        alt={product[0].productName}
                      />
                    </a>
                </div>
                <div className="card-body px-0">
                  <div className="fs-xs">
                    <a className="text-muted" href="shop.html">
                      {product[0].categoryName}
                    </a>
                  </div>
                  <div className="fw-bold">
                    <a className="text-body" href="product.html">
                      {product[0].productName}
                    </a>
                  </div>
                  <div className="fw-bold text-muted">
                    {product[0].productPrice}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Revenue;
