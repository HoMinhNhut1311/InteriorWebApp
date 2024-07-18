package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.CartService;
import com.hominhnhut.WMN_BackEnd.service.Interface.PageService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/cart")
@Slf4j
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CartController {
    CartService cartService;
    PageService pageService;
    @GetMapping("")
    public ResponseEntity<List<CartResponse>> getAllCart(){
        List<CartResponse> cartResponses = cartService.getAllCart();
        return ResponseEntity.ok(cartResponses);
    }
    @GetMapping("/{id}")
    public ResponseEntity<CartResponse> findCartById(@PathVariable String id){
        CartResponse cartResponse = cartService.findCartById(id);
        return  ResponseEntity.ok(cartResponse);
    }

    @PostMapping("")
    public ResponseEntity<CartResponse> saveCart(@RequestBody CartRequest cartRequest){
        System.out.println(cartRequest);
        CartResponse cartResponse = cartService.saveCart(cartRequest);
        return ResponseEntity.ok(cartResponse);
    }
    @PutMapping("/{id}")
    public ResponseEntity<CartResponse> updateCart(@RequestBody CartRequest cartRequest,@PathVariable String id){
        CartResponse cartResponse = cartService.updateCart(cartRequest,id);
        return ResponseEntity.ok(cartResponse);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCart(@PathVariable String id){
        cartService.deleteCart(id);
        return ResponseEntity.noContent().build();
    }
    @GetMapping("/page")
    public ResponseEntity<Page<CartResponse>> getPageCartByUser(
            @RequestParam("userId") String userId,
            @RequestParam("pageNumber") Integer pageNumber,
            @RequestParam("pageSize") Integer pageSize
    ){
        Page<CartResponse> cartResponses = pageService.getPageCartByUserId(pageNumber,pageSize,userId);
        return ResponseEntity.ok(cartResponses);
    }
}


