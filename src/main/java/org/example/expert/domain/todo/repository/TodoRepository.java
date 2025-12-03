package org.example.expert.domain.todo.repository;

import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface TodoRepository extends JpaRepository<Todo, Long> {

    // 0. 수동 fetch join.
    // 1. 전체 조회용 : 나머진 쿼리 메서드가 해줄 것.
    @EntityGraph(attributePaths="user")
    Page<Todo> findAllByOrderByModifiedAtDesc(Pageable pageable);

    // 2. 단건 조회용
    // 3. 기타 : new
    @EntityGraph(attributePaths="user")
    @Query("SELECT t FROM Todo t WHERE t.id = :todoId")
    Optional<Todo> findByIdWithUser(@Param("todoId") Long todoId);

    int countById(Long todoId);
}
