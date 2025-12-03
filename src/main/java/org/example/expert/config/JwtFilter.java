package org.example.expert.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// 0. 순번 달아둔 건 내가 직접 판단하고 작성한 것.
@Slf4j
@RequiredArgsConstructor
public class JwtFilter implements Filter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 1. 형변환을 했네?
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String url = httpRequest.getRequestURI();

        // 2. 시작지점이 /auth면 다른 필터로 위임 : 화이트리스트 세팅과 비슷해보인다. : 로그인 입구는 열어두는 식
        if (url.startsWith("/auth")) {
            chain.doFilter(request, response);
            return;
        }

        // 3. 헤더 체크
        String bearerJwt = httpRequest.getHeader("Authorization");

        // 4. 퍼블릭 또는 익명 접근
        if (bearerJwt == null) {
            log.warn("인증 헤더 누락: URI={}", url);
            sendErrorResponse(httpResponse, HttpStatus.UNAUTHORIZED, "인증이 필요합니다.");
            return;
        }

        // 5. Bearer 7자 substringToken이라는 곳에서 -7. substringToken에 예외처리로 분기가 이어짐.
        String jwt = jwtUtil.substringToken(bearerJwt);

        try {
            // JWT 유효성 검사와 claims 추출
            Claims claims = jwtUtil.extractClaims(jwt);
            // 6. 내용물 null : 내 필터랑 다르네
            if (claims == null) {
                log.warn("Claims 추출 실패: URI={}", url);
                sendErrorResponse(httpResponse, HttpStatus.UNAUTHORIZED, "인증이 필요합니다.");
                return;
            }

            UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

            // 7. 이게 ArgumentResolver로 갈 내용.
            httpRequest.setAttribute("userId", Long.parseLong(claims.getSubject()));
            httpRequest.setAttribute("email", claims.get("email"));
            httpRequest.setAttribute("userRole", claims.get("userRole"));

            // 8. Admin 권한 검사를 필터에 넣은 모습.
            if (url.startsWith("/admin") && !UserRole.ADMIN.equals(userRole)) {
                log.warn("권한 부족: userId={}, role={}, URI={}", claims.getSubject(), userRole, url);
                sendErrorResponse(httpResponse, HttpStatus.FORBIDDEN, "접근 권한이 없습니다.");
                return;
            }

            chain.doFilter(request, response);
            // 9. validation check를 아예 catch에 다 압축 시켜놨네?
        } catch (ExpiredJwtException e) {
            log.info("JWT 만료: userId={}, URI={}", e.getClaims().getSubject(), url);
            sendErrorResponse(httpResponse, HttpStatus.UNAUTHORIZED, "인증이 필요합니다.");
        } catch (SecurityException | MalformedJwtException | UnsupportedJwtException e) {
            log.error("JWT 검증 실패 [{}]: URI={}", e.getClass().getSimpleName(), url, e);
            sendErrorResponse(httpResponse, HttpStatus.BAD_REQUEST, "인증이 필요합니다.");
        } catch (Exception e) {
            log.error("예상치 못한 오류: URI={}", url, e);
            sendErrorResponse(httpResponse, HttpStatus.INTERNAL_SERVER_ERROR, "요청 처리 중 오류가 발생했습니다.");
        }
    }

    // 10. AccessDeniedHandler - AuthenticationEntryPoint와 유사한 구조의 응답
    private void sendErrorResponse(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json;charset=UTF-8");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", status.name());
        errorResponse.put("code", status.value());
        errorResponse.put("message", message);

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
// 11. 전반적으로 검증, ContextHolder -> resolver 내용, 권한 체크를 다 몰아서 한 것으로 해석 중.
