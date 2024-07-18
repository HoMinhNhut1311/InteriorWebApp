package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.config.PaymentConfig;
import com.hominhnhut.WMN_BackEnd.domain.enity.Cart;
import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.PaymentResponse;
import com.hominhnhut.WMN_BackEnd.domain.response.ProductResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.CartService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/payment")
@Slf4j
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class PaymentController {
    CartService cartService;
    static CartRequest cart;

    @GetMapping("/createPayment")
    public ResponseEntity<PaymentResponse> createPayment(
            @RequestParam("amount") Long amount,
            @RequestParam("localDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate localDate,
            @RequestParam("status") Boolean status,
            @RequestParam("username") String username,
            @RequestParam("productIds") List<String> productIds
    ) throws UnsupportedEncodingException {
        if (cart == null) {
            cart = new CartRequest();
        }
        String orderType = "other";
        cart.setLocalDate(localDate);
        cart.setStatus(status);
        cart.setUsername(username);
        cart.setProductIds(productIds);
        log.info("cartId: {}", cart.toString());
//        long amount = Integer.parseInt(req.getParameter("amount")) * 100;
//        String bankCode = req.getParameter("bankCode");

        String vnp_TxnRef = PaymentConfig.getRandomNumber(8);
        double v = .1;
        String vnp_IpAddr = "192.168.1.6";

        String vnp_TmnCode = PaymentConfig.vnp_TmnCode;

        Map<String, String> vnp_Params = new HashMap<>();
        vnp_Params.put("vnp_Version", PaymentConfig.vnp_Version);
        vnp_Params.put("vnp_Command", PaymentConfig.vnp_Command);
        vnp_Params.put("vnp_TmnCode", vnp_TmnCode);
        vnp_Params.put("vnp_Amount", String.valueOf(amount * 100L));
        vnp_Params.put("vnp_CurrCode", "VND");

        vnp_Params.put("vnp_BankCode", "NCB");
        vnp_Params.put("vnp_TxnRef", vnp_TxnRef);
        vnp_Params.put("vnp_OrderInfo", "Thanh toan don hang:" + vnp_TxnRef);
        vnp_Params.put("vnp_OrderType", orderType);

        vnp_Params.put("vnp_Locale", "vn");
        vnp_Params.put("vnp_ReturnUrl", PaymentConfig.vnp_ReturnUrl);
        vnp_Params.put("vnp_IpAddr", vnp_IpAddr);

        Calendar cld = Calendar.getInstance(TimeZone.getTimeZone("Etc/GMT+7"));
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
        String vnp_CreateDate = formatter.format(cld.getTime());
        vnp_Params.put("vnp_CreateDate", vnp_CreateDate);

        cld.add(Calendar.MINUTE, 15);
        String vnp_ExpireDate = formatter.format(cld.getTime());
        vnp_Params.put("vnp_ExpireDate", vnp_ExpireDate);

        List fieldNames = new ArrayList(vnp_Params.keySet());
        Collections.sort(fieldNames);
        StringBuilder hashData = new StringBuilder();
        StringBuilder query = new StringBuilder();
        Iterator itr = fieldNames.iterator();
        while (itr.hasNext()) {
            String fieldName = (String) itr.next();
            String fieldValue = (String) vnp_Params.get(fieldName);
            if ((fieldValue != null) && (fieldValue.length() > 0)) {
                //Build hash data
                hashData.append(fieldName);
                hashData.append('=');
                hashData.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                //Build query
                query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString()));
                query.append('=');
                query.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                if (itr.hasNext()) {
                    query.append('&');
                    hashData.append('&');
                }
            }
        }
        String queryUrl = query.toString();
        String vnp_SecureHash = PaymentConfig.hmacSHA512(PaymentConfig.secretKey, hashData.toString());
        queryUrl += "&vnp_SecureHash=" + vnp_SecureHash;
        String paymentUrl = PaymentConfig.vnp_PayUrl + "?" + queryUrl;

//        com.google.gson.JsonObject job = new JsonObject();
//        job.addProperty("code", "00");
//        job.addProperty("message", "success");
//        job.addProperty("data", paymentUrl);
//        Gson gson = new Gson();
//        resp.getWriter().write(gson.toJson(job));

        PaymentResponse paymentResponse = new PaymentResponse();
        paymentResponse.setStatus("Ok");
        paymentResponse.setMessage("Successfully");
        paymentResponse.setURL(paymentUrl);
        return ResponseEntity.ok(paymentResponse);
    }

    @GetMapping("/return")
    public ResponseEntity<Void> returnPage(@RequestParam Map<String, String> requestParams) {
        PaymentResponse paymentResponse = new PaymentResponse();
        log.info("payment response: {}", requestParams);
        List<String> fieldNames = new ArrayList<>(requestParams.keySet());
        Collections.sort(fieldNames);
        StringBuilder hashData = new StringBuilder();
        for (String fieldName : fieldNames) {
            String fieldValue = requestParams.get(fieldName);
            if (fieldValue != null && fieldValue.length() > 0) {
                hashData.append(fieldName).append('=').append(fieldValue);
                if (fieldNames.indexOf(fieldName) < fieldNames.size() - 1) {
                    hashData.append('&');
                }
            }
        }
        if ("00".equals(requestParams.get("vnp_ResponseCode")) && "00".equals(requestParams.get("vnp_TransactionStatus"))) {
            CartRequest cartRequest = cart;
            cartService.saveCart(cartRequest);
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create("http://localhost:5173/user/success"));
            return new ResponseEntity<>(headers, HttpStatus.SEE_OTHER);
        } else {
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create("http://localhost:5173/user/failure"));
            return new ResponseEntity<>(headers, HttpStatus.SEE_OTHER);
        }
    }
}
